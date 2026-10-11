///|
/// A parameter of a tool signature.
pub(all) struct Param {
  name : String
  type_ : String
  required : Bool
  doc : String
} derive(Debug, Eq)

///|
pub fn Param::new(
  name : String,
  type_ : String,
  required? : Bool = true,
  doc? : String = "",
) -> Param {
  { name, type_, required, doc, }
}

///|
/// A tool the plan may call. The interpreter never performs the call itself:
/// it checks the policy and then asks its driver to perform it.
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
/// What a tool returns: the JSON result and how its parts are labelled. Every
/// part is labelled as coming from the tool; `paths` adds the external
/// authors and reader restrictions of individual parts (see `json_to_item`).
pub(all) struct ToolResult {
  value : Json
  readers : @label.Readers
  paths : PathLabels
} derive(Debug)

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
} derive(Debug)

///|
/// Everything a human needs to decide on a call that needs confirmation.
pub(all) struct ConfirmRequest {
  tool : String
  args : Map[String, Json]
  reason : String
  /// For each offending argument (or `<context>`), where its data came from.
  provenance : Array[(String, String)]
} derive(Debug)

///|
/// An interaction with the outside world.
///
/// The interpreter itself is pure. When a plan reaches an effect whose
/// response has not been recorded yet, the run stops and reports the effect;
/// the driver performs it, records the response in the `Memo`, and runs the
/// plan again. Replays are deterministic, so the plan reaches the same point
/// and continues with the recorded response.
pub(all) enum Effect {
  /// Perform a tool call the policy has allowed.
  CallTool(tool~ : String, args~ : Map[String, Json])
  /// Ask the quarantined LLM to extract a value of type `schema` from
  /// `prompt`. `json_schema` describes the same type as a JSON Schema.
  AskQuarantined(prompt~ : String, schema~ : TypeSpec, json_schema~ : Json)
  /// Ask the user to approve a call the policy could not prove safe.
  Confirm(request~ : ConfirmRequest)
} derive(Debug)

///|
/// The response to an effect.
pub(all) enum Response {
  ToolOk(ToolResult)
  ToolError(String)
  Quarantined(QAnswer)
  Approval(Bool)
} derive(Debug)

///|
/// Responses to effects already performed in a session, keyed by the
/// identity of the effect and its occurrence number within a run.
///
/// The key does not depend on *when* an effect happens. A corrected plan that
/// repeats a call made by an earlier attempt receives the recorded response
/// instead of performing the call again, so within a session every distinct
/// side effect happens at most once.
pub(all) struct Memo {
  entries : Map[String, Response]
}

///|
pub fn Memo::new() -> Memo {
  { entries: Map([]), }
}

///|
pub fn Memo::get(self : Memo, key : String) -> Response? {
  self.entries.get(key)
}

///|
pub fn Memo::add(self : Memo, key : String, response : Response) -> Unit {
  self.entries[key] = response
}

///|
pub fn Memo::length(self : Memo) -> Int {
  self.entries.length()
}

///|
/// The identity of an effect, independent of when it is requested.
pub fn Effect::identity(self : Effect) -> String {
  match self {
    CallTool(tool~, args~) =>
      "tool:\{tool}:" + canonical_json(Json::object(args))
    AskQuarantined(prompt~, schema~, ..) =>
      "ask:\{schema.name}:" + canonical_json(Json::string(prompt))
    Confirm(request~) =>
      "confirm:\{request.tool}:\{request.reason}:" +
      canonical_json(Json::object(request.args))
  }
}

///|
/// JSON text with object keys in sorted order, so equal values always have
/// the same text.
pub fn canonical_json(j : Json) -> String {
  match j {
    Object(m) => {
      let keys = m.keys().collect()
      keys.sort_by((a, b) => a.lexical_compare(b))
      "{" +
      keys
      .map(k => Json::string(k).stringify() + ":" + canonical_json(m[k]))
      .join(",") +
      "}"
    }
    Array(xs) => "[" + xs.map(canonical_json).join(",") + "]"
    other => other.stringify()
  }
}

///|
/// Performs effects synchronously.
///
/// Tests and simple embeddings implement this trait and call `drive`.
/// Asynchronous drivers (network, user interface) call `run_plan` with a
/// `Memo` themselves and perform the reported effect however they like.
pub(open) trait Host {
  fn perform(Self, Effect) -> Response
}
