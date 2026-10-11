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
/// answers; the user is played by the visitor, who decides on approvals.

///|
priv struct Model {
  scenario : Int
  plan : String
  injection : String
  q_answer : String
  policy : String
  approve : Bool
  ran : Bool
} derive(Eq)

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
}

///|
fn initial(i : Int) -> Model {
  let s = scenarios()[i]
  {
    scenario: i,
    plan: s.plan,
    injection: s.injection,
    q_answer: s.q_answer,
    policy: @banking.policy_text,
    approve: s.approve,
    ran: true,
  }
}

///|
fn update(model : Model, msg : Msg) -> Model {
  match msg {
    Pick(i) => initial(i)
    EditPlan(p) => { ..model, plan: p, ran: false, }
    EditInjection(t) => { ..model, injection: t, ran: false, }
    EditAnswer(a) => { ..model, q_answer: a, ran: false, }
    EditPolicy(p) => { ..model, policy: p, ran: false, }
    ToggleApprove => { ..model, approve: !model.approve, ran: false, }
    Run => { ..model, ran: true, }
    Reset => initial(model.scenario)
  }
}

///|
fn main {
  @rabbita.new(app).mount("app")
}

///|
fn app() -> @rabbita.Val[@html.Html] {
  let (model, emit) = @rabbita.create_pure_state(initial(0), update~)
  model.view(m => view(m, emit))
}
