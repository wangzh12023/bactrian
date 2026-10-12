///|
/// One event of a run, in order. The trace is what the playground draws and
/// what the planner is told after a run.
pub(all) enum Event {
  /// A tool call was checked against the policy.
  ToolCall(
    id~ : Int,
    tool~ : String,
    args~ : Map[String, Json],
    arg_labels~ : Map[String, @label.Label],
    context~ : @label.Label,
    verdict~ : @policy.Verdict,
    approved~ : Bool?,
    result~ : Json?,
    result_label~ : @label.Label?,
    span~ : @basic.Span
  )
  /// The quarantined LLM was asked to extract a value.
  Quarantined(
    id~ : Int,
    schema~ : String,
    prompt_label~ : @label.Label,
    answer~ : Json?,
    span~ : @basic.Span
  )
  /// The plan printed something for the user.
  Print(text~ : String, label~ : @label.Label)
}

///|
/// Limits that keep any plan finite and cheap.
pub(all) struct Limits {
  /// Maximum number of evaluation steps.
  max_steps : Int
  /// Maximum number of tool and quarantined-LLM calls.
  max_calls : Int
  /// Maximum length of any list built by the plan.
  max_list : Int
  /// Maximum nesting of lambda calls.
  max_depth : Int
}

///|
pub fn Limits::default() -> Limits {
  { max_steps: 200_000, max_calls: 64, max_list: 100_000, max_depth: 32, }
}

///|
/// The world a plan runs in: the tools it may call, the record types it may
/// use, the policy that guards its effects, and the host that performs them.
pub(all) struct World {
  tools : Map[String, ToolSpec]
  types : Map[String, TypeSpec]
  policy : @policy.Policy
  limits : Limits
}

///|
pub fn World::new(
  tools : Array[ToolSpec],
  types : Array[TypeSpec],
  policy : @policy.Policy,
  limits? : Limits = Limits::default(),
) -> World {
  let tm : Map[String, ToolSpec] = Map([])
  for t in tools {
    tm[t.name] = t
  }
  let ym : Map[String, TypeSpec] = Map([])
  for t in types {
    ym[t.name] = t
  }
  { tools: tm, types: ym, policy, limits, }
}

///|
/// The tool signatures in the form `@policy.Policy::validate` expects.
pub fn World::signatures(self : World) -> Map[String, Array[String]] {
  let m : Map[String, Array[String]] = Map([])
  for name, t in self.tools {
    m[name] = t.params.map(p => p.name)
  }
  m
}

///|
/// Mutable state of one run. Variables survive between runs of a session so
/// the planner can fix a failing plan without repeating effects.
pub(all) struct Session {
  globals : Map[String, Item]
  plan_types : Map[String, TypeSpec]
  events : Array[Event]
  output : Array[(String, @label.Label)]
  mut next_id : Int
  mut steps : Int
  mut calls : Int
}

///|
pub fn Session::new() -> Session {
  {
    globals: Map([]),
    plan_types: Map([]),
    events: [],
    output: [],
    next_id: 1,
    steps: 0,
    calls: 0,
  }
}

///|
/// The text the plan printed, in order.
pub fn Session::printed(self : Session) -> String {
  self.output.map(p => p.0).join("\n")
}
