///|
/// What a policy decided about one tool call.
pub(all) enum Decision {
  Allow
  Deny(String)
  /// The call is not provably safe, but a human may approve it after seeing
  /// where its arguments came from.
  Ask(String)
} derive(Eq, Debug)

///|
/// What a policy sees of one argument: its JSON value and the label of
/// everything reachable from it (for a list, the join of all its elements and
/// of whatever decided its length and order).
pub(all) struct ArgView {
  value : Json
  label : @label.Label
}

///|
/// The facts available to a policy when the interpreter is about to perform a
/// tool call.
pub(all) struct CallView {
  tool : String
  args : Map[String, ArgView]
  /// Label of the control context: everything that decided whether this call
  /// is reached at all (enclosing `if` conditions, `for` iterables, early
  /// `break`s).
  context : @label.Label
}

///|
pub fn CallView::arg(self : CallView, name : String) -> ArgView? {
  self.args.get(name)
}

///|
/// A condition over a tool call. Conditions are data: a policy can be
/// printed, parsed, and checked against tool signatures before it is used.
pub(all) enum Cond {
  /// Every source of the argument (deep) is trusted.
  Trusted(String)
  /// The argument is readable by anyone.
  Public(String)
  /// Every listed principal may read the argument.
  ReadableBy(String, Array[String])
  /// The control context is trusted: no untrusted data decided whether the
  /// call happens.
  ContextTrusted
  /// The argument is a number not greater than the bound.
  AtMost(String, Double)
  /// The argument equals one of the listed JSON values.
  OneOf(String, Array[Json])
  /// The argument is present and not `None`.
  Present(String)
  All(Array[Cond])
  Any(Array[Cond])
  Not(Cond)
} derive(Debug)

///|
pub(all) enum Severity {
  /// Deny the call.
  Block
  /// Ask the user, showing the provenance of the offending data.
  Confirm
} derive(Eq, Debug)

///|
/// One rule: when `cond` fails, `otherwise` decides, and `reason` explains the
/// rule in human terms.
pub(all) struct Rule {
  cond : Cond
  otherwise : Severity
  reason : String
} derive(Debug)

///|
pub(all) enum ToolKind {
  /// Has no side effect visible to anyone but the user: always allowed.
  Read
  /// Has a side effect: subject to the built-in flow checks and the rules.
  Effect
} derive(Eq, Debug)

///|
/// The policy of one tool.
///
/// `audience` names the arguments that identify who will observe the effect
/// (the recipients of an e-mail, the payee of a transfer). For an effect with
/// an audience the engine enforces, before any rule, that every other
/// argument and the control context are readable by that audience — the
/// "no exfiltration" guarantee.
pub(all) struct ToolPolicy {
  tool : String
  kind : ToolKind
  audience : Array[String]
  rules : Array[Rule]
} derive(Debug)

///|
/// A complete security policy.
pub(all) struct Policy {
  name : String
  tools : Map[String, ToolPolicy]
  /// Tools that are systems of record: data they return is trusted unless a
  /// part is attributed to an untrusted party.
  trusted_tools : Array[String]
  /// External parties whose content is trusted.
  trusted_parties : Array[String]
  /// Identifiers of the user (e-mail addresses, account numbers). The user
  /// may always read everything and is trusted as a party.
  self_ids : Array[String]
  /// When set, an effect reached under untrusted control flow is blocked or
  /// needs confirmation even if its arguments are fine.
  context_integrity : Severity?
  /// Decision for a tool without a policy entry.
  unknown_tool : Decision
}

///|
pub fn Policy::new(
  name : String,
  tools : Array[ToolPolicy],
  trusted_tools? : Array[String] = [],
  trusted_parties? : Array[String] = [],
  self_ids? : Array[String] = [],
  context_integrity? : Severity,
  unknown_tool? : Decision = Deny("no policy covers this tool"),
) -> Policy {
  let m : Map[String, ToolPolicy] = Map([])
  for t in tools {
    m[t.tool] = t
  }
  {
    name,
    tools: m,
    trusted_tools,
    trusted_parties,
    self_ids,
    context_integrity,
    unknown_tool,
  }
}

///|
/// The trust rule of this policy: the user and the plan are always trusted;
/// a tool or a party only when the policy says so.
pub fn Policy::trusts(self : Policy, source : @label.Source) -> Bool {
  match source {
    User | Plan => true
    Tool(name) => self.trusted_tools.contains(name)
    Party(name) =>
      self.trusted_parties.contains(name) || self.self_ids.contains(name)
  }
}

///|
pub fn Policy::is_trusted(self : Policy, label : @label.Label) -> Bool {
  label.is_trusted(s => self.trusts(s))
}

///|
/// Builder for a tool without side effects.
pub fn read(tool : String) -> ToolPolicy {
  { tool, kind: Read, audience: [], rules: [], }
}

///|
/// Builder for a side-effecting tool.
pub fn effect(
  tool : String,
  audience? : Array[String] = [],
  rules : Array[Rule],
) -> ToolPolicy {
  { tool, kind: Effect, audience, rules, }
}

///|
pub fn require(cond : Cond, reason : String) -> Rule {
  { cond, otherwise: Block, reason, }
}

///|
pub fn confirm(cond : Cond, reason : String) -> Rule {
  { cond, otherwise: Confirm, reason, }
}
