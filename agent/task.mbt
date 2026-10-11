///|
/// One message of a chat conversation.
pub(all) struct Message {
  role : String
  content : String
} derive(Debug, Eq, ToJson)

///|
/// What the agent loop needs from the outside world. Like the interpreter,
/// the loop is sans-IO: it reports what it needs, and its driver performs it
/// and hands the answer back.
pub(all) enum Need {
  /// Ask the planner (the privileged LLM) for a program.
  Plan(messages~ : Array[Message])
  /// Perform an effect of the running program; answer with
  /// `Task::give_response(key, response)`.
  Run(key~ : String, effect~ : @runtime.Effect)
}

///|
/// How a task ended.
pub(all) enum Final {
  /// The program ran to completion; `output` is what it printed.
  Done(output~ : String)
  /// The policy blocked an action. The planner is not allowed to try another
  /// way around a denial: a denial means that, as requested, untrusted data
  /// would decide something it must not.
  Blocked(tool~ : String, reason~ : String)
  /// The user declined an action that needed confirmation.
  Declined(tool~ : String, reason~ : String)
  /// The planner did not produce a working program.
  GaveUp(reason~ : String)
} derive(Debug)

///|
/// One attempt: the program the planner wrote and how running it ended.
pub(all) struct Attempt {
  code : String
  outcome : String
} derive(Debug)

///|
/// The state of one task. Everything is plain data, so a driver can store a
/// task, display it, or replay it from a recording.
pub(all) struct Task {
  world : @runtime.World
  request : String
  max_attempts : Int
  mode : @runtime.Mode
  /// The conversation with the planner so far.
  messages : Array[Message]
  /// Responses to the effects performed so far, shared by all attempts.
  memo : @runtime.Memo
  /// The planner's replies, in order.
  replies : Array[String]
  attempts : Array[Attempt]
  /// The session of the latest run (trace and printed output).
  mut session : @runtime.Session?
  mut ending : Final?
}

///|
pub fn Task::new(
  world : @runtime.World,
  request : String,
  persona? : String = "",
  notes? : Array[String] = [],
  examples? : Array[String] = [],
  max_attempts? : Int = 4,
  mode? : @runtime.Mode = Strict,
) -> Task {
  {
    world,
    request,
    max_attempts,
    mode,
    messages: [
      {
        role: "system",
        content: planner_prompt(world, persona~, notes~, examples~),
      },
      { role: "user", content: request, },
    ],
    memo: @runtime.Memo::new(),
    replies: [],
    attempts: [],
    session: None,
    ending: None,
  }
}

///|
/// Advances the task as far as possible without outside help. Returns what
/// the driver must provide next, or `None` once the task has ended (see
/// `ending`).
pub fn Task::step(self : Task) -> Need? {
  for ;; {
    if self.ending is Some(_) {
      return None
    }
    if self.attempts.length() == self.replies.length() {
      // Every reply so far has been tried: ask for a new program.
      if self.attempts.length() >= self.max_attempts {
        self.ending = Some(
          GaveUp(
            reason="no working program after \{self.max_attempts} attempts",
          ),
        )
        return None
      }
      return Some(Plan(messages=self.messages.copy()))
    }
    let reply = self.replies[self.replies.length() - 1]
    guard extract_code(reply) is Some(code) else {
      self.retry(
        reply, "Your reply did not contain a ```python code block. Reply with exactly one code block.",
      )
      continue
    }
    let (outcome, session) = @runtime.run_once(
      self.world,
      self.memo,
      code,
      mode=self.mode,
    )
    self.session = Some(session)
    match outcome {
      Suspended(key~, effect~) => return Some(Run(key~, effect~))
      Completed => {
        self.attempts.push({ code, outcome: "completed", })
        self.ending = Some(Done(output=session.printed()))
      }
      Failed(e) =>
        match e.kind() {
          PolicyDenied(tool~) => {
            self.attempts.push({ code, outcome: "blocked by the policy", })
            self.ending = Some(Blocked(tool~, reason=e.message()))
          }
          NotApproved(tool~) => {
            self.attempts.push({ code, outcome: "declined by the user", })
            self.ending = Some(Declined(tool~, reason=e.message()))
          }
          Budget => {
            self.attempts.push({ code, outcome: e.message(), })
            self.ending = Some(GaveUp(reason=e.message()))
          }
          _ => self.retry(code, feedback(code, e, self.world.policy))
        }
    }
  }
}

///|
/// Records a failed attempt and tells the planner what went wrong.
fn Task::retry(self : Task, code : String, message : String) -> Unit {
  self.attempts.push({ code, outcome: message, })
  self.messages.push({
    role: "assistant",
    content: self.replies[self.replies.length() - 1],
  })
  self.messages.push({ role: "user", content: message, })
}

///|
/// Records the planner's reply to the last `Plan` need.
pub fn Task::give_plan(self : Task, reply : String) -> Unit {
  self.replies.push(reply)
}

///|
/// Records the response to the effect of the last `Run` need.
pub fn Task::give_response(
  self : Task,
  key : String,
  response : @runtime.Response,
) -> Unit {
  self.memo.add(key, response)
}

///|
/// The error message shown to the planner after a failed run.
///
/// It never contains data derived from untrusted sources. When the error was
/// caused by such data, the planner learns the line and the kind of error,
/// but not the message: otherwise an attacker could talk to the planner
/// through exception messages (`int("ignore previous instructions...")`).
pub fn feedback(
  code : String,
  e : @runtime.PlanError,
  policy : @policy.Policy,
) -> String {
  let line = e.span().start.line
  let source_line = match code.split("\n").collect().get(line - 1) {
    Some(l) => l.trim().to_owned()
    None => ""
  }
  let kind = e.kind()
  let detail = if kind is (Syntax | Unsupported) || policy.is_trusted(e.label()) {
    e.message()
  } else {
    "<details removed: they depend on untrusted data>"
  }
  let advice = match kind {
    NotEnoughInformation =>
      "\nPut all the data the assistant needs into the query, or look the information up with a tool first."
    Syntax | Unsupported => "\nUse only the language features listed above."
    _ => ""
  }
  (
    $|Running the program failed at line \{line}:
    $|
    $|    \{source_line}
    $|
    $|\{kind.python_name()}: \{detail}\{advice}
    $|
    $|Send the whole corrected program. Tool calls that already happened are
    $|not repeated: their recorded results are reused.
  )
}
