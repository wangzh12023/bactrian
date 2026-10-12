///|
/// The playground: one page, three panes.
///
/// 1. The scenario: the user's request, the planner's program (editable),
///    and the attacker's text (editable) planted in the documents.
/// 2. The run: every tool call with its verdict and the provenance of its
///    arguments, side by side with the same run without a policy.
/// 3. The policy (editable, re-validated on every change).
///
/// Everything runs in the browser: the interpreter, the policy engine and the
/// simulated bank are the same MoonBit code as the CLI, compiled to JS. The
/// quarantined assistant is played by the attacker, who decides what it
/// answers; the user is played by the visitor, who decides on approvals. A
/// fifth tab ("live") lets a real model write the plan.

///|
priv struct Model {
  scenario : Int
  plan : String
  injection : String
  q_answer : String
  policy : String
  approve : Bool
  ran : Bool
  live : Live
  live_result : LiveResult?
}

///|
/// The outcome of a live run.
priv struct LiveResult {
  task : @agent.Task
  pre : @banking.Bank
  post : @banking.Bank
}

///|
impl Eq for Model with fn equal(a, b) {
  a.scenario == b.scenario &&
  a.plan == b.plan &&
  a.injection == b.injection &&
  a.q_answer == b.q_answer &&
  a.policy == b.policy &&
  a.approve == b.approve &&
  a.ran == b.ran &&
  a.live == b.live &&
  (match (a.live_result, b.live_result) {
    (None, None) => true
    (Some(x), Some(y)) => physical_equal(x, y)
    _ => false
  })
}

///|
/// Index of the live tab.
let live_tab : Int = 4

///|
priv enum Msg {
  Pick(Int)
  EditPlan(String)
  EditInjection(String)
  EditAnswer(String)
  EditPolicy(String)
  ToggleApprove
  Run
  Reset
  LiveEdit((Live) -> Live)
  LiveStart
  LiveDone(Result[(@agent.Task, @banking.Bank, @banking.Bank), String])
}

///|
fn initial(i : Int, live? : Live = Live::default()) -> Model {
  let s = scenarios()[if i == live_tab { 0 } else { i }]
  {
    scenario: i,
    plan: s.plan,
    injection: s.injection,
    q_answer: s.q_answer,
    policy: @banking.policy_text,
    approve: s.approve,
    ran: true,
    live,
    live_result: None,
  }
}

///|
fn update(
  model : Model,
  msg : Msg,
  emit : @rabbita.Emit[Msg],
) -> (Model, @rabbita.Cmd) {
  match msg {
    Pick(i) => (initial(i, live=model.live), @rabbita.none)
    EditPlan(p) => ({ ..model, plan: p, ran: false, }, @rabbita.none)
    EditInjection(t) => ({ ..model, injection: t, ran: false, }, @rabbita.none)
    EditAnswer(a) => ({ ..model, q_answer: a, ran: false, }, @rabbita.none)
    EditPolicy(p) => ({ ..model, policy: p, ran: false, }, @rabbita.none)
    ToggleApprove =>
      ({ ..model, approve: !model.approve, ran: false, }, @rabbita.none)
    Run => ({ ..model, ran: true, }, @rabbita.none)
    Reset => (initial(model.scenario, live=model.live), @rabbita.none)
    LiveEdit(f) => {
      let live = f(model.live)
      // The stored key follows the form: updated while "remember" is ticked,
      // removed the moment it is unticked.
      if live.remember != model.live.remember ||
        live.api_key != model.live.api_key {
        save_key(live)
      }
      ({ ..model, live, }, @rabbita.none)
    }
    LiveStart => {
      let live = { ..model.live, status: Planning, }
      save_settings(live)
      (
        { ..model, live, live_result: None, },
        @rabbita.perform(r => (emit.0)(LiveDone(r)), () => run_live(live)),
      )
    }
    LiveDone(Ok((task, pre, post))) =>
      (
        {
          ..model,
          live: { ..model.live, status: Finished, },
          live_result: Some({ task, pre, post, }),
        },
        @rabbita.none,
      )
    LiveDone(Err(msg)) =>
      (
        { ..model, live: { ..model.live, status: Failed(msg), }, },
        @rabbita.none,
      )
  }
}

///|
fn main {
  @rabbita.new(app).mount("app")
}

///|
fn app() -> @rabbita.Val[@html.Html] {
  let (model, emit) = @rabbita.create_state(initial(0), update~)
  model.view(m => view(m, emit))
}
