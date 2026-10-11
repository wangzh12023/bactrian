///|
/// How labels follow control flow.
pub(all) enum Mode {
  /// Values written under a condition carry the condition's label, and so do
  /// variables a skipped branch would have written (no implicit flows).
  Strict
  /// Only explicit data dependencies are tracked, like CaMeL's NORMAL mode.
  /// Effects are still checked against the control context.
  Normal
} derive(Eq, Debug)

///|
/// The result of one run of a plan.
pub(all) enum Outcome {
  /// The plan ran to the end.
  Completed
  /// The plan stopped at an effect whose response is not yet recorded. The
  /// driver performs it, adds the response to the memo with `Memo::add(key,
  /// response)`, and runs the plan again.
  Suspended(key~ : String, effect~ : Effect)
  /// The plan failed.
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
/// Runs a plan once.
///
/// The run is a pure function of the plan, the world and the memo: every
/// effect it needs is looked up in `memo`, and the first one that is missing
/// suspends the run. Each run starts from a fresh session, so a suspended run
/// simply runs again once the response is known.
pub fn run_once(
  world : World,
  memo : Memo,
  source : String,
  mode? : Mode = Strict,
) -> (Outcome, Session) {
  let session = Session::new()
  let m = parse_plan(source) catch { e => return (Failed(e), session) }
  let ctx : Ctx = {
    world,
    session,
    memo,
    seen: Map([]),
    scopes: [],
    pc: @label.Label::bottom(),
    exit: Ref(@label.Label::bottom()),
    strict: mode is Strict,
  }
  let flow = ctx.exec_block(m.body) catch {
    PlanError(kind=Pending(effect), ..) => {
      let identity = effect.identity()
      let n = ctx.seen.get(identity).unwrap_or(1) - 1
      return (Suspended(key="\{n}|\{identity}", effect~), session)
    }
    e => return (Failed(e), session)
  }
  match flow {
    Normal => (Completed, session)
    Break | Continue =>
      (
        Failed(unsupported("`break`/`continue` outside a loop", m.span)),
        session,
      )
  }
}

///|
/// Runs a plan to the end, performing its effects with `host`.
///
/// Returns the final outcome (never `Suspended`) and the session of the last
/// run, which holds the trace and the printed output.
pub fn drive(
  world : World,
  host : &Host,
  source : String,
  memo? : Memo = Memo::new(),
  mode? : Mode = Strict,
) -> (Outcome, Session) {
  for ;; {
    match run_once(world, memo, source, mode~) {
      (Suspended(key~, effect~), _) => memo.add(key, host.perform(effect))
      done => return done
    }
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
