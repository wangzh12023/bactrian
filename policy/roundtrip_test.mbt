///|
/// Random policies for round-trip properties. Names and reasons are drawn
/// from small alphabets that need no escaping; the parser and renderer are
/// tested on quoting separately.
priv struct APolicy(@policy.Policy)

///|
impl @debug.Debug for APolicy with fn to_repr(self) {
  @debug.Repr::string(self.0.render())
}

///|
let arg_names : Array[String] = ["to", "amount", "body", "recipient", "id"]

///|
fn pick_name(rs : @qc.RandomState, xs : Array[String]) -> String {
  xs[rs.next_uint(limit=xs.length().reinterpret_as_uint()).reinterpret_as_int()]
}

///|
fn gen_cond(rs : @qc.RandomState, depth : Int) -> @policy.Cond {
  let a = pick_name(rs, arg_names)
  let leaf = rs.next_uint(limit=7).reinterpret_as_int()
  if depth > 0 && rs.next_uint(limit=3) == 0 {
    let n = 1 + rs.next_uint(limit=2).reinterpret_as_int()
    let cs = Array::makei(n, _ => gen_cond(rs, depth - 1))
    match rs.next_uint(limit=3) {
      0 => All(cs)
      1 => Any(cs)
      _ => Not(cs[0])
    }
  } else {
    match leaf {
      0 => Trusted(a)
      1 => Public(a)
      2 =>
        ReadableBy(
          a,
          ["bob", "carol"][:1 + rs.next_uint(limit=2).reinterpret_as_int()].to_owned(),
        )
      3 => ContextTrusted
      4 => AtMost(a, rs.next_uint(limit=5000).reinterpret_as_int().to_double())
      5 => OneOf(a, [Json::string("x"), Json::number(1.0), Json::boolean(true)])
      _ => Present(a)
    }
  }
}

///|
impl @qc.Arbitrary for APolicy with fn arbitrary(_, rs) {
  let tools = []
  let used = []
  for i in 0..<(1 + rs.next_uint(limit=4).reinterpret_as_int()) {
    let name = "tool_\{i}"
    used.push(name)
    if rs.next_uint(limit=3) == 0 {
      tools.push(@policy.read(name))
    } else {
      let audience = if rs.next_uint(limit=2) == 0 {
        []
      } else {
        [pick_name(rs, arg_names)]
      }
      let rules = Array::makei(rs.next_uint(limit=3).reinterpret_as_int(), j => {
        let cond = gen_cond(rs, 2)
        if rs.next_uint(limit=2) == 0 {
          @policy.require(cond, "rule \{j}")
        } else {
          @policy.confirm(cond, "rule \{j}")
        }
      })
      tools.push(@policy.effect(name, audience~, rules))
    }
  }
  APolicy(
    @policy.Policy::new(
      "generated",
      tools,
      trusted_tools=used.filter(_ => rs.next_uint(limit=2) == 0),
      self_ids=if rs.next_uint(limit=2) == 0 { ["me"] } else { [] },
      context_integrity?=match rs.next_uint(limit=3) {
        0 => Some(@policy.Severity::Block)
        1 => Some(@policy.Severity::Confirm)
        _ => None
      },
    ),
  )
}

///|
impl @qc.Shrink for APolicy

///|
test "rendering a policy and parsing it back is the identity" {
  @qc.check(
    fn(p : APolicy) {
      let text = p.0.render()
      let back = @policy.parse_policy(text) catch { _ => return false }
      back.render() == text
    },
    count=500,
  )
}
