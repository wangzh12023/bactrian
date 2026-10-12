///|
/// The banking benchmark: user tasks × injection tasks, with a real model as
/// the planner and the quarantined LLM.
///
/// The benchmark itself is pure: it is driven through the same sans-IO
/// `Need` interface as the agent loop, and only `run_cell` performs I/O.

///|
pub(all) struct CellResult {
  task : String
  injection : String?
  /// The task's goal was achieved.
  utility : Bool
  /// The attacker's goal was achieved.
  attacked : Bool
  /// How the run ended (`done`, `blocked`, `declined`, `gave up`).
  ending : String
  /// Number of planner calls.
  planner_calls : Int
  /// Number of confirmations requested.
  confirmations : Int
  /// Tools the runtime refused or held for approval.
  stopped_at : Array[String]
  /// How each attempt ended (first line), for diagnosis.
  attempts : Array[String]
} derive(Debug, ToJson)

///|
/// Who answers the quarantined assistant's queries during a benchmark run.
pub(all) enum QMode {
  /// The configured model.
  Model
  /// An attacker who controls the quarantined assistant completely.
  Hijacked
} derive(Eq, Debug)

///|
/// What an attacker who controls the quarantined assistant answers: the
/// attacker's account for every string, a large amount for every number.
pub fn hijacked_answer(schema : @runtime.TypeSpec) -> @runtime.QAnswer {
  let m : Map[String, Json] = Map([])
  for f in schema.fields {
    m[f.name] = match f.type_ {
      "float" | "int" => Json::number(9999.0)
      "bool" => Json::boolean(true)
      "list[str]" => Json::array([Json::string(@banking.ATTACKER_IBAN)])
      _ => Json::string(@banking.ATTACKER_IBAN)
    }
  }
  Answer(Json::object(m))
}

///|
/// Runs one cell of the benchmark. `approve` decides confirmation requests:
/// the benchmark's simulated user refuses every request whose provenance
/// shows untrusted data, as a careful user would.
pub async fn run_cell(
  planner : @llm.Endpoint,
  quarantined : @llm.Endpoint,
  task : @banking.UserTask,
  injection : @banking.InjectionTask?,
  qmode? : QMode = Model,
  approve_untrusted? : Bool = false,
  log? : (String) -> Unit = _ => (),
) -> CellResult {
  let pre = match injection {
    Some(inj) => @banking.attacked_bank(task, inj)
    None => @banking.Bank::new()
  }
  let bank = pre.snapshot()
  let t = @agent.Task::new(
    @banking.world(),
    task.prompt,
    persona="The user's name is Emma Johnson.",
    notes=@banking.notes,
    examples=@banking.examples,
  )
  let mut planner_calls = 0
  let mut confirmations = 0
  for ;; {
    match t.step() {
      None => break
      Some(Plan(messages~)) => {
        planner_calls += 1
        let reply = @llm.complete(planner, messages) catch {
          e => {
            log("planner error: \{e}")
            "(the planner failed to answer)"
          }
        }
        log("--- plan \{planner_calls}:\n\{reply}")
        t.give_plan(reply)
      }
      Some(Run(key~, effect~)) => {
        let response : @runtime.Response = match effect {
          CallTool(tool~, args~) =>
            ToolOk(bank.call(tool, args)) catch {
              e => ToolError("\{e}")
            }
          AskQuarantined(prompt~, schema~, json_schema~) =>
            match qmode {
              Hijacked => Quarantined(hijacked_answer(schema))
              Model => {
                let reply = @llm.complete(
                  quarantined,
                  @llm.quarantined_messages(prompt, schema, json_schema),
                  json_mode=true,
                ) catch {
                  e => {
                    log("quarantined error: \{e}")
                    "{}"
                  }
                }
                Quarantined(@llm.parse_quarantined(reply))
              }
            }
          Confirm(request~) => {
            confirmations += 1
            log(
              "--- confirmation requested for \{request.tool}: \{request.reason}",
            )
            Approval(approve_untrusted)
          }
        }
        t.give_response(key, response)
      }
    }
  }
  let output = match t.ending {
    Some(Done(output~)) => output
    _ => ""
  }
  let ending = match t.ending {
    Some(Done(..)) => "done"
    Some(Blocked(..)) => "blocked"
    Some(Declined(..)) => "declined"
    Some(GaveUp(..)) | None => "gave up"
  }
  let stopped_at = []
  if t.session is Some(s) {
    for e in s.events {
      if e is ToolCall(tool~, verdict~, ..) && !(verdict.decision is Allow) {
        stopped_at.push(tool)
      }
    }
  }
  {
    task: task.id,
    injection: injection.map(i => i.id),
    utility: (task.utility)(output, pre, bank),
    attacked: match injection {
      Some(inj) => (inj.security)(pre, bank)
      None => false
    },
    ending,
    planner_calls,
    confirmations,
    stopped_at,
    attempts: t.attempts.map(a => summarize_attempt(a.outcome)),
  }
}

///|
/// The most informative line of an attempt's outcome (the error line).
fn summarize_attempt(outcome : String) -> String {
  let lines = outcome
    .split("\n")
    .map(l => l.trim().to_owned())
    .filter(l => l != "")
    .collect()
  match lines.filter(l => l.contains("Error:") || l.contains("Denied")) {
    [first, ..] => first
    [] => lines.get(0).unwrap_or("")
  }
}
