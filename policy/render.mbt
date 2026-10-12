///|
/// Renders a condition in the syntax of policy files.
pub fn Cond::render(self : Cond) -> String {
  match self {
    Trusted(a) => "trusted(\{a})"
    Public(a) => "public(\{a})"
    ReadableBy(a, ps) => "readable_by(\{a}, [" + quoted(ps) + "])"
    ContextTrusted => "context_trusted"
    AtMost(a, n) => "at_most(\{a}, \{n})"
    OneOf(a, js) =>
      "one_of(\{a}, [" + js.map(j => j.stringify()).join(", ") + "])"
    Present(a) => "present(\{a})"
    All(cs) => "all(" + cs.map(c => c.render()).join(", ") + ")"
    Any(cs) => "any(" + cs.map(c => c.render()).join(", ") + ")"
    Not(c) => "not(" + c.render() + ")"
  }
}

///|
/// A string literal of the policy language: the string written as a JSON
/// string, so quotes, backslashes and control characters are escaped the way
/// `parse_policy` reads them back.
fn quote(s : String) -> String {
  Json::string(s).stringify()
}

///|
fn quoted(xs : Array[String]) -> String {
  xs.map(quote).join(", ")
}

///|
/// Renders a whole policy in the policy file syntax (see `parse_policy`);
/// `parse_policy(p.render())` reproduces `p`.
pub fn Policy::render(self : Policy) -> String {
  let out = StringBuilder()
  out.write_string("policy \{quote(self.name)}\n")
  if !self.self_ids.is_empty() {
    out.write_string("self \{quoted(self.self_ids)}\n")
  }
  if !self.trusted_tools.is_empty() {
    out.write_string("trust tools \{self.trusted_tools.join(", ")}\n")
  }
  if !self.trusted_parties.is_empty() {
    out.write_string("trust parties \{quoted(self.trusted_parties)}\n")
  }
  match self.context_integrity {
    Some(Block) => out.write_string("context require\n")
    Some(Confirm) => out.write_string("context confirm\n")
    None => ()
  }
  match self.unknown_tool {
    Allow => out.write_string("unknown allow\n")
    Ask(_) => out.write_string("unknown confirm\n")
    Deny(_) => ()
  }
  let names = self.tools.keys().collect()
  names.sort_by((a, b) => a.lexical_compare(b))
  for name in names {
    let tp = self.tools[name]
    out.write_string("\n")
    match tp.kind {
      Read => out.write_string("read \{name}\n")
      Effect => {
        out.write_string("effect \{name}")
        if !tp.audience.is_empty() {
          out.write_string(" audience \{tp.audience.join(", ")}")
        }
        out.write_string("\n")
        for rule in tp.rules {
          let verb = match rule.otherwise {
            Block => "require"
            Confirm => "confirm"
          }
          out.write_string(
            "  \{verb} \{rule.cond.render()} : \{quote(rule.reason)}\n",
          )
        }
      }
    }
  }
  out.to_string()
}
