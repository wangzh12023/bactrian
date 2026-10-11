///|
/// How labels follow control flow.
pub(all) enum Mode {
  /// Values created under a condition carry the condition's label, and so do
  /// variables a skipped branch would have written (no implicit flows).
  Strict
  /// Only explicit data dependencies are tracked, like CaMeL's NORMAL mode.
  /// Effects are still checked against the control context.
  Normal
} derive(Eq, Debug)

///|
/// The result of running a plan.
pub(all) enum Outcome {
  Completed
  Failed(PlanError)
}

///|
/// Parses a plan without running it. Syntax errors are reported with the
/// position of the offending token.
pub fn parse_plan(source : String) -> @ast.Module raise PlanError {
  @parser.parse_string(source, name="plan") catch {
    @pyerr.PurePyError(d) =>
      raise err(Syntax, d.message(), d.span.unwrap_or(@basic.nowhere))
    e => raise err(Syntax, "\{e}", @basic.nowhere)
  }
}

///|
/// Runs a plan in `session`. Effects go through `host`; every tool call is
/// checked against `world.policy` first. Variables assigned by the plan stay
/// in the session, so a corrected plan can continue where a failing one
/// stopped without repeating its effects.
pub fn run_plan(
  world : World,
  host : &Host,
  session : Session,
  source : String,
  mode? : Mode = Strict,
) -> Outcome {
  let m = parse_plan(source) catch { e => return Failed(e) }
  run_module(world, host, session, m, mode~)
}

///|
pub fn run_module(
  world : World,
  host : &Host,
  session : Session,
  m : @ast.Module,
  mode? : Mode = Strict,
) -> Outcome {
  let ctx : Ctx = {
    world,
    host,
    session,
    scopes: [],
    pc: @label.Label::bottom(),
    exit: Ref(@label.Label::bottom()),
    strict: mode is Strict,
  }
  let flow = ctx.exec_block(m.body) catch { e => return Failed(e) }
  match flow {
    Normal => Completed
    Break | Continue =>
      Failed(unsupported("`break`/`continue` outside a loop", m.span))
  }
}

///|
/// Looks up a variable the plan assigned.
pub fn Session::get(self : Session, name : String) -> Item? {
  self.globals.get(name)
}

///|
/// Every tool call the plan made, with its verdict.
pub fn Session::tool_calls(self : Session) -> Array[Event] {
  self.events.filter(e => e is ToolCall(..))
}
