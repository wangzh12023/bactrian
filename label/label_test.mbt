///|
/// A small universe keeps generated reader sets overlapping often enough for
/// the lattice laws to be exercised on interesting cases.
let principals : Array[String] = ["alice", "bob", "carol", "mallory"]

///|
let tools : Array[String] = ["read_file", "get_balance", "search"]

///|
priv struct ALabel(@label.Label) derive(Debug)

///|
fn gen_source(rs : @qc.RandomState) -> @label.Source {
  match rs.next_uint(limit=4) {
    0 => User
    1 => Plan
    _ =>
      Tool(
        tools[rs
        .next_uint(limit=tools.length().reinterpret_as_uint())
        .reinterpret_as_int()],
      )
  }
}

///|
fn gen_readers(rs : @qc.RandomState) -> @label.Readers {
  if rs.next_uint(limit=3) == 0 {
    Public
  } else {
    @label.Readers::only(principals.filter(_ => rs.next_uint(limit=2) == 0))
  }
}

///|
impl @qc.Arbitrary for ALabel with fn arbitrary(_, rs) {
  let sources = Array::makei(rs.next_uint(limit=3).reinterpret_as_int(), _ => {
    gen_source(rs)
  })
  let origins = Array::makei(rs.next_uint(limit=3).reinterpret_as_int(), _ => {
    rs.next_uint(limit=5).reinterpret_as_int()
  })
  ALabel({
    sources: @iset.SortedSet(sources),
    readers: gen_readers(rs),
    origins: @iset.SortedSet(origins),
  })
}

///|
impl @qc.Shrink for ALabel

///|
test "join is commutative, associative and idempotent" {
  @qc.check(fn(t : (ALabel, ALabel, ALabel)) {
    let (ALabel(a), ALabel(b), ALabel(c)) = t
    a.join(b) == b.join(a) &&
    a.join(b).join(c) == a.join(b.join(c)) &&
    a.join(a) == a
  })
}

///|
test "bottom is the identity of join" {
  @qc.check(fn(a : ALabel) {
    let ALabel(a) = a
    @label.Label::bottom().join(a) == a && a.join(@label.Label::bottom()) == a
  })
}

///|
test "join is an upper bound and flows_to is the lattice order" {
  @qc.check(fn(t : (ALabel, ALabel)) {
    let (ALabel(a), ALabel(b)) = t
    let j = a.join(b)
    a.flows_to(j) &&
    b.flows_to(j) &&
    // a <= b  <=>  a join b == b
    a.flows_to(b) == (j == b)
  })
}

///|
test "joining never makes data more trusted or more readable" {
  @qc.check(fn(t : (ALabel, ALabel)) {
    let (ALabel(a), ALabel(b)) = t
    let j = a.join(b)
    let trust = @label.default_trusted
    j.is_trusted(trust) == (a.is_trusted(trust) && b.is_trusted(trust)) &&
    principals
    .iter()
    .all(p => {
      j.readers.allows([p]) == (a.readers.allows([p]) && b.readers.allows([p]))
    })
  })
}

///|
test "constructors and rendering" {
  let user = @label.Label::user()
  let plan = @label.Label::plan()
  let bill = @label.Label::tool(
    "read_file",
    readers=@label.Readers::only(["emma"]),
    origin=3,
  )
  inspect(plan.render(), content="plan|public")
  inspect(user.join(plan).render(), content="user+plan|public")
  inspect(bill.render(), content="tool:read_file|{emma}")
  inspect(bill.join(plan).render(), content="plan+tool:read_file|{emma}")
  assert_true(plan.is_trusted(@label.default_trusted))
  assert_false(bill.join(plan).is_trusted(@label.default_trusted))
  debug_inspect(
    bill.join(plan).untrusted_sources(@label.default_trusted),
    content=(
      #|[Tool("read_file")]
    ),
  )
  json_inspect(bill, content={
    "sources": ["tool:read_file"],
    "readers": ["emma"],
    "origins": [3],
  })
}

///|
test "reader sets intersect when data is combined" {
  let a = @label.Readers::only(["alice", "bob"])
  let b = @label.Readers::only(["bob", "carol"])
  inspect(a.meet(b).render(), content="{bob}")
  inspect(a.meet(Public).render(), content="{alice, bob}")
  assert_true(a.allows(["bob", "alice"]))
  assert_false(a.allows(["carol"]))
  assert_true(@label.Readers::Public.allows(["anyone"]))
  assert_true(a.meet(b).within(a))
  assert_false(@label.Readers::Public.within(a))
}
