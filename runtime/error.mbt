///|
/// Why the interpreter stopped. Every error carries the source span of the
/// statement or expression that raised it.
pub(all) enum ErrorKind {
  /// The plan could not be parsed.
  Syntax
  /// The plan uses a construct outside the plan language.
  Unsupported
  /// A Python-level error: `TypeError`, `KeyError`, `ValueError`, ...
  Runtime(String)
  /// A tool call was denied by the policy.
  PolicyDenied(tool~ : String)
  /// The user declined a call that needed confirmation.
  NotApproved(tool~ : String)
  /// The quarantined LLM said the data did not contain enough information.
  NotEnoughInformation
  /// The host failed to perform a tool call.
  ToolFailed(tool~ : String)
  /// The plan exceeded the step budget.
  Budget
  /// Not an error: the run stopped at an effect the driver must perform.
  Pending(Effect)
} derive(Debug)

///|
pub(all) suberror PlanError {
  PlanError(
    kind~ : ErrorKind,
    message~ : String,
    span~ : @basic.Span,
    label~ : @label.Label
  )
} derive(Debug)

///|
/// The label of the data that caused the error. Messages derived from
/// untrusted data are redacted before they are shown to the planner.
pub fn PlanError::label(self : PlanError) -> @label.Label {
  let PlanError(label~, ..) = self
  label
}

///|
pub fn PlanError::kind(self : PlanError) -> ErrorKind {
  let PlanError(kind~, ..) = self
  kind
}

///|
pub fn PlanError::message(self : PlanError) -> String {
  let PlanError(message~, ..) = self
  message
}

///|
pub fn PlanError::span(self : PlanError) -> @basic.Span {
  let PlanError(span~, ..) = self
  span
}

///|
/// Python's name for the error, as shown in a traceback.
pub fn ErrorKind::python_name(self : ErrorKind) -> String {
  match self {
    Syntax => "SyntaxError"
    Unsupported => "NotSupportedError"
    Runtime(name) => name
    PolicyDenied(..) => "SecurityPolicyDenied"
    NotApproved(..) => "NotApprovedByUser"
    NotEnoughInformation => "NotEnoughInformationError"
    ToolFailed(..) => "ToolError"
    Budget => "BudgetExceeded"
    Pending(_) => "Pending"
  }
}

///|
fn err(
  kind : ErrorKind,
  message : String,
  span : @basic.Span,
  label? : @label.Label = @label.Label::plan(),
) -> PlanError {
  PlanError(kind~, message~, span~, label~)
}

///|
fn type_error(
  message : String,
  span : @basic.Span,
  label? : @label.Label = @label.Label::plan(),
) -> PlanError {
  err(Runtime("TypeError"), message, span, label~)
}

///|
fn unsupported(message : String, span : @basic.Span) -> PlanError {
  err(Unsupported, message, span)
}
