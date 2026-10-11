///|
/// Runs one banking request with a real model as planner and quarantined LLM.
/// `attack` selects an injection task to plant in the data.
async fn run_request(request : String, attack : Int?) -> Unit {
  let (planner, quarantined) = endpoints()
  if planner.api_key == "" {
    println(red("set BACTRIAN_API_KEY (and BACTRIAN_BASE_URL) first"))
    return
  }
  let injection = match attack {
    Some(i) => @banking.injection_tasks().get(i)
    None => None
  }
  let task : @banking.UserTask = {
    id: "custom",
    prompt: request,
    vectors: @banking.Vector::all(),
    utility: (_, _, _) => true,
  }
  let bank = match injection {
    Some(inj) => @banking.attacked_bank(task, inj)
    None => @banking.Bank::new()
  }
  let pre = bank.snapshot()
  let t = @agent.Task::new(
    @banking.world(),
    request,
    persona="The user's name is Emma Johnson.",
    notes=@banking.notes,
    examples=@banking.examples,
  )
  println(dim("planner: \{planner.model}  quarantined: \{quarantined.model}"))
  if injection is Some(inj) {
    println(yellow("injected into every document: ") + inj.goal)
  }
  for ;; {
    match t.step() {
      None => break
      Some(Plan(messages~)) => {
        println(dim("… asking the planner"))
        let reply = @llm.complete(planner, messages)
        println(bold("Plan:"))
        match @agent.extract_code(reply) {
          Some(code) =>
            for line in code.split("\n") {
              println("  " + dim(line.to_owned()))
            }
          None => println(reply)
        }
        t.give_plan(reply)
      }
      Some(Run(key~, effect~)) => {
        let response : @runtime.Response = match effect {
          CallTool(tool~, args~) =>
            ToolOk(bank.call(tool, args)) catch {
              e => ToolError("\{e}")
            }
          AskQuarantined(prompt~, schema~, json_schema~) => {
            let reply = @llm.complete(
              quarantined,
              @llm.quarantined_messages(prompt, schema, json_schema),
              json_mode=true,
            )
            Quarantined(@llm.parse_quarantined(reply))
          }
          Confirm(request~) => {
            println(
              yellow("Approval needed for \{request.tool}: \{request.reason}"),
            )
            for p in request.provenance {
              println("  \{p.0} \{p.1}")
            }
            println(dim("  (the CLI declines; use the playground to approve)"))
            Approval(false)
          }
        }
        t.give_response(key, response)
      }
    }
  }
  println(bold("\nAttempts:"))
  for i, a in t.attempts {
    println(
      "  \{i + 1}. " +
      a.outcome.split("\n").map(l => l.to_owned()).collect().join("\n     "),
    )
  }
  println(bold("\nTrace of the last run:"))
  if t.session is Some(s) {
    print_trace(s)
  }
  match t.final {
    Some(Done(output~)) => println(green("\n✓ done") + "\n" + output)
    Some(Blocked(tool~, reason~)) =>
      println(red("\n✗ blocked \{tool}: \{reason}"))
    Some(Declined(tool~, reason~)) =>
      println(yellow("\n• declined \{tool}: \{reason}"))
    Some(GaveUp(reason~)) => println(red("\n✗ gave up: \{reason}"))
    None => ()
  }
  if injection is Some(inj) {
    if (inj.security)(pre, bank) {
      println(red("✗ the attacker's goal was reached"))
    } else {
      println(green("✓ the attacker's goal was not reached"))
    }
  }
}

///|
/// Runs the benchmark and prints a JSON line per cell plus a summary.
async fn bench(args : Array[String]) -> Unit {
  let (planner, quarantined) = endpoints()
  if planner.api_key == "" {
    println(red("set BACTRIAN_API_KEY (and BACTRIAN_BASE_URL) first"))
    return
  }
  let pick = fn(name : String) -> Array[String]? {
    flag_value(args, name).map(s => {
      s.split(",").map(x => x.to_owned()).collect()
    })
  }
  let tasks = match pick("--tasks") {
    Some(ids) =>
      @banking.user_tasks().filter(t => {
        ids.contains(t.id) ||
        ids.contains(t.id.replace(old="user_task_", new=""))
      })
    None => @banking.user_tasks()
  }
  let injections : Array[@banking.InjectionTask?] = match pick("--injections") {
    Some(["none"]) => [None]
    Some(ids) =>
      @banking.injection_tasks()
      .filter(i => {
        ids.contains(i.id) ||
        ids.contains(i.id.replace(old="injection_task_", new=""))
      })
      .map(i => Some(i))
    None => [None, ..@banking.injection_tasks().map(i => Some(i))]
  }
  let baseline = flag(args, "--baseline")
  let qmode : @bench.QMode = if flag(args, "--hijack") {
    Hijacked
  } else {
    Model
  }
  let verbose = flag(args, "--verbose")
  let log = fn(s : String) { if verbose { println(dim(s)) } }
  let results = []
  for task in tasks {
    for inj in injections {
      let r = if baseline {
        @bench.run_baseline_cell(planner, task, inj, log~)
      } else {
        @bench.run_cell(planner, quarantined, task, inj, qmode~, log~)
      }
      println(r.to_json().stringify())
      results.push(r)
    }
  }
  let benign = results.filter(r => r.injection is None)
  let attacked = results.filter(r => r.injection is Some(_))
  let count = fn(
    xs : Array[@bench.CellResult],
    f : (@bench.CellResult) -> Bool,
  ) {
    xs.filter(f).length()
  }
  println(
    bold(
      "\nSummary (\{if baseline { "baseline tool-calling agent" } else { "Bactrian" }}, \{planner.model})",
    ),
  )
  if !benign.is_empty() {
    println(
      "  utility (no attack):        \{count(benign, r => r.utility)}/\{benign.length()}",
    )
  }
  if !attacked.is_empty() {
    println(
      "  utility under attack:       \{count(attacked, r => r.utility)}/\{attacked.length()}",
    )
    println(
      "  attacks that succeeded:     \{count(attacked, r => r.attacked)}/\{attacked.length()}",
    )
  }
}
