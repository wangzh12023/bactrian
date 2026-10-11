///|
/// One reason a call is not plainly allowed.
pub(all) struct Concern {
  severity : Severity
  reason : String
  /// The argument whose data triggered the concern, or `"<context>"` when it
  /// is the control flow that leads to the call.
  culprit : String
  /// The label of the offending data; explanations walk its provenance.
  label : @label.Label
} derive(Debug)

///|
/// The outcome of checking one call.
pub(all) struct Verdict {
  decision : Decision
  concerns : Array[Concern]
} derive(Debug)

///|
pub const CONTEXT : String = "<context>"

///|
/// Checks one tool call against the policy.
///
/// The check fails closed: an unknown tool is decided by `unknown_tool`
/// (deny by default) and an audience argument that does not name principals
/// is denied.
///
/// For a side-effecting tool the engine first enforces confidentiality
/// against the tool's audience: unless the audience itself was chosen by the
/// user or the plan, every other argument — and the control context — must be
/// readable by everyone in the audience. Then the optional context-integrity
/// check runs, then the tool's own rules. Any `Block` concern denies the call;
/// otherwise any `Confirm` concern asks the user; otherwise it is allowed.
pub fn Policy::check(self : Policy, call : CallView) -> Verdict {
  let tp = match self.tools.get(call.tool) {
    Some(tp) => tp
    None => return { decision: self.unknown_tool, concerns: [], }
  }
  if tp.kind is Read {
    return { decision: Allow, concerns: [], }
  }
  let concerns : Array[Concern] = []
  if !tp.audience.is_empty() {
    match self.audience_of(tp, call) {
      None =>
        return {
          decision: Deny(
            "the audience of `\{call.tool}` must be a name or a list of names",
          ),
          concerns: [],
        }
      Some((audience, audience_trusted)) =>
        if !audience_trusted && !audience.is_empty() {
          let who = audience.join(", ")
          for name, arg in call.args {
            if tp.audience.contains(name) {
              continue
            }
            if !arg.label.readers.allows(audience) {
              concerns.push({
                severity: Block,
                reason: "`\{name}` contains data that \{who} is not allowed to read, and \{who} was not chosen by you",
                culprit: name,
                label: arg.label,
              })
            }
          }
          if !call.context.readers.allows(audience) {
            concerns.push({
              severity: Block,
              reason: "whether this happens depends on data that \{who} is not allowed to read",
              culprit: CONTEXT,
              label: call.context,
            })
          }
        }
    }
  }
  if self.context_integrity is Some(severity) && !self.is_trusted(call.context) {
    concerns.push({
      severity,
      reason: "this action only happens because of a decision made on untrusted data",
      culprit: CONTEXT,
      label: call.context,
    })
  }
  for rule in tp.rules {
    if self.failing_argument(rule.cond, call) is Some(culprit) {
      let label = if culprit == CONTEXT {
        call.context
      } else {
        match call.arg(culprit) {
          Some(a) => a.label
          None => @label.Label::bottom()
        }
      }
      concerns.push({
        severity: rule.otherwise,
        reason: rule.reason,
        culprit,
        label,
      })
    }
  }
  let decision = match concerns.search_by(c => c.severity is Block) {
    Some(i) => Deny(concerns[i].reason)
    None =>
      if concerns.is_empty() {
        Allow
      } else {
        Ask(concerns.map(c => c.reason).join("; "))
      }
  }
  { decision, concerns, }
}

///|
/// The principals named by the tool's audience arguments (without the user's
/// own identities), and whether all of those arguments are trusted. `None`
/// when an audience argument is not a string or a list of strings.
fn Policy::audience_of(
  self : Policy,
  tp : ToolPolicy,
  call : CallView,
) -> (Array[String], Bool)? {
  let names : Array[String] = []
  let mut trusted = true
  for a in tp.audience {
    match call.arg(a) {
      None => continue
      Some(arg) => {
        match principals_of(arg.value) {
          Some(ps) =>
            for p in ps {
              if !self.self_ids.contains(p) && !names.contains(p) {
                names.push(p)
              }
            }
          None => return None
        }
        trusted = trusted && self.is_trusted(arg.label)
      }
    }
  }
  Some((names, trusted))
}

///|
/// `None` when the condition holds, otherwise `Some(argument)` naming the
/// argument that made it fail.
fn Policy::failing_argument(
  self : Policy,
  cond : Cond,
  call : CallView,
) -> String? {
  match cond {
    Trusted(name) =>
      match call.arg(name) {
        Some(a) if !self.is_trusted(a.label) => Some(name)
        _ => None
      }
    Public(name) =>
      match call.arg(name) {
        Some(a) if a.label.readers != @label.Readers::Public => Some(name)
        _ => None
      }
    ReadableBy(name, principals) =>
      match call.arg(name) {
        Some(a) if !a.label.readers.allows(principals) => Some(name)
        _ => None
      }
    ContextTrusted =>
      if self.is_trusted(call.context) {
        None
      } else {
        Some(CONTEXT)
      }
    AtMost(name, bound) =>
      match call.arg(name) {
        Some({ value: Number(n, ..), .. }) if n <= bound => None
        _ => Some(name)
      }
    OneOf(name, choices) =>
      match call.arg(name) {
        Some(a) if choices.iter().any(c => c == a.value) => None
        _ => Some(name)
      }
    Present(name) =>
      match call.arg(name) {
        Some({ value: Null, .. }) | None => Some(name)
        Some(_) => None
      }
    All(cs) => {
      for c in cs {
        if self.failing_argument(c, call) is Some(culprit) {
          return Some(culprit)
        }
      }
      None
    }
    Any(cs) => {
      let mut first : String? = None
      for c in cs {
        match self.failing_argument(c, call) {
          None => return None
          Some(culprit) => if first is None { first = Some(culprit) }
        }
      }
      // `any()` of nothing is false, like Python's.
      Some(first.unwrap_or(CONTEXT))
    }
    Not(c) =>
      match self.failing_argument(c, call) {
        None =>
          Some(
            match c.arguments() {
              [first, ..] => first
              [] => CONTEXT
            },
          )
        Some(_) => None
      }
  }
}

///|
/// Reads an audience argument: a string or a list of strings.
fn principals_of(v : Json) -> Array[String]? {
  match v {
    String(s) => Some([s])
    Null => Some([])
    Array(xs) => {
      let out = []
      for x in xs {
        match x {
          String(s) => out.push(s)
          _ => return None
        }
      }
      Some(out)
    }
    _ => None
  }
}

///|
/// The argument names a condition refers to.
pub fn Cond::arguments(self : Cond) -> Array[String] {
  match self {
    ContextTrusted => []
    Trusted(a)
    | Public(a)
    | ReadableBy(a, _)
    | AtMost(a, _)
    | OneOf(a, _)
    | Present(a) => [a]
    All(cs) | Any(cs) => {
      let out = []
      for c in cs {
        out.append(c.arguments())
      }
      out
    }
    Not(c) => c.arguments()
  }
}

///|
/// Checks the policy against tool signatures (tool name to parameter names)
/// and returns every inconsistency found. An empty result means every rule
/// talks about arguments that exist and every tool has a policy.
pub fn Policy::validate(
  self : Policy,
  signatures : Map[String, Array[String]],
) -> Array[String] {
  let problems = []
  for tool, tp in self.tools {
    match signatures.get(tool) {
      None => problems.push("policy for unknown tool `\{tool}`")
      Some(params) => {
        for a in tp.audience {
          if !params.contains(a) {
            problems.push(
              "`\{tool}`: audience refers to unknown argument `\{a}`",
            )
          }
        }
        for rule in tp.rules {
          for a in rule.cond.arguments() {
            if !params.contains(a) {
              problems.push(
                "`\{tool}`: rule `\{rule.cond.render()}` refers to unknown argument `\{a}`",
              )
            }
          }
        }
      }
    }
  }
  for tool, _ in signatures {
    if !self.tools.contains(tool) {
      problems.push(
        "no policy for tool `\{tool}`: calls will be decided by the default",
      )
    }
  }
  problems
}
