///|
/// A parameter of a tool signature.
pub(all) struct Param {
  name : String
  type_ : String
  required : Bool
} derive(Debug, Eq)

///|
/// A tool the plan may call. The interpreter never performs the call itself:
/// it checks the policy and then asks the `Host` to do it.
pub(all) struct ToolSpec {
  name : String
  params : Array[Param]
  returns : String
  doc : String
} derive(Debug)

///|
/// A field of a record type (a tool result type or a plan-declared schema).
pub(all) struct FieldSpec {
  name : String
  type_ : String
  doc : String
} derive(Debug, Eq)

///|
pub(all) struct TypeSpec {
  name : String
  fields : Array[FieldSpec]
  doc : String
} derive(Debug)

///|
/// What the host returns for one tool call: the JSON result and how its parts
/// should be labelled. Every part is labelled as coming from the tool; `paths`
/// adds the external authors and reader restrictions of individual parts
/// (see `json_to_item`).
pub(all) struct ToolResult {
  value : Json
  readers : @label.Readers
  paths : PathLabels
}

///|
pub fn ToolResult::plain(
  value : Json,
  readers? : @label.Readers = Public,
) -> ToolResult {
  { value, readers, paths: PathLabels::empty(), }
}

///|
/// The quarantined LLM's answer: either a value matching the schema, or a
/// statement that the data did not contain enough information.
pub(all) enum QAnswer {
  Answer(Json)
  NotEnoughInformation
}

///|
/// The effects the interpreter needs from its environment.
///
/// Everything that touches the outside world goes through this trait, which
/// makes the interpreter deterministic and replayable: a host can perform real
/// calls, serve a recording, or be an adversary in a test.
pub(open) trait Host {
  /// Performs a tool call that the policy already allowed.
  fn call_tool(Self, String, Map[String, Json]) -> ToolResult raise
  /// Asks the quarantined LLM to extract a value of type `schema` from
  /// `prompt`. The model has no tools; its output is labelled with every
  /// source of the prompt.
  fn ask_quarantined(Self, String, TypeSpec) -> QAnswer raise
  /// Asks the user to approve a call the policy could not prove safe.
  fn confirm(Self, ConfirmRequest) -> Bool
}

///|
/// Everything a human needs to decide on a call that needs confirmation.
pub(all) struct ConfirmRequest {
  tool : String
  args : Map[String, Json]
  reason : String
  /// For each argument, where its data came from.
  provenance : Array[(String, String)]
}
