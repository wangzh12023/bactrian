///|
/// Random policies for round-trip properties. Argument and tool names are
/// identifiers; the strings (the policy's name, principals, the user's ids
/// and the reasons) are drawn from an alphabet that needs escaping — quotes,
/// backslashes, `#`, newlines, control characters and non-ASCII text — so the
/// property also covers quoting. Hand-written quoting cases are in
/// `policy_test.mbt` ("quoted strings use JSON escapes ...").
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
/// Pieces of the strings in generated policies.
let string_pieces : Array[String] = [
  "rule", " ", "\"", "\\", "\\\"", "#", ":", ",", "(", ")", "\n", "\t", "\u{01}",
  "/", "é", "付款", "😀", "\\u0041",
]

///|
fn gen_string(rs : @qc.RandomState) -> String {
  let sb = StringBuilder()
  for _ in 0..<rs.next_uint(limit=6).reinterpret_as_int() {
    sb.write_string(pick_name(rs, string_pieces))
  }
  sb.to_string()
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
          Array::makei(1 + rs.next_uint(limit=2).reinterpret_as_int(), _ => {
            gen_string(rs)
          }),
        )
      3 => ContextTrusted
      4 => AtMost(a, rs.next_uint(limit=5000).reinterpret_as_int().to_double())
      5 =>
        OneOf(a, [
          Json::string(gen_string(rs)),
          Json::number(1.0),
          Json::boolean(true),
        ])
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
        let reason = "rule \{j}" + gen_string(rs)
        if rs.next_uint(limit=2) == 0 {
          @policy.require(cond, reason)
        } else {
          @policy.confirm(cond, reason)
        }
      })
      tools.push(@policy.effect(name, audience~, rules))
    }
  }
  APolicy(
    @policy.Policy::new(
      gen_string(rs),
      tools,
      trusted_tools=used.filter(_ => rs.next_uint(limit=2) == 0),
      self_ids=if rs.next_uint(limit=2) == 0 {
        ["me", gen_string(rs)]
      } else {
        []
      },
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

///|
test "parsing keeps every string of a rendered policy" {
  // `render` is a function of the policy, so comparing renderings is the
  // identity only if no string is lost or altered on the way: check the
  // strings themselves too.
  @qc.check(
    fn(p : APolicy) {
      let back = @policy.parse_policy(p.0.render()) catch { _ => return false }
      let reasons = (q : @policy.Policy) => {
        let names = q.tools.keys().collect()
        names.sort_by((a, b) => a.lexical_compare(b))
        names.map(n => q.tools[n].rules.map(r => r.reason))
      }
      back.name == p.0.name &&
      back.self_ids == p.0.self_ids &&
      reasons(back) == reasons(p.0)
    },
    count=300,
  )
}
