///|
/// ANSI styling for terminal output.
fn bold(s : String) -> String {
  "\u{1b}[1m\{s}\u{1b}[0m"
}

///|
fn red(s : String) -> String {
  "\u{1b}[31m\{s}\u{1b}[0m"
}

///|
fn green(s : String) -> String {
  "\u{1b}[32m\{s}\u{1b}[0m"
}

///|
fn yellow(s : String) -> String {
  "\u{1b}[33m\{s}\u{1b}[0m"
}

///|
fn dim(s : String) -> String {
  "\u{1b}[2m\{s}\u{1b}[0m"
}

///|
/// Prints the trace of a run: every checked tool call with its verdict and
/// the provenance of its arguments.
fn print_trace(session : @runtime.Session) -> Unit {
  for e in session.events {
    match e {
      ToolCall(id~, tool~, args~, arg_labels~, verdict~, approved~, ..) => {
        let shown = args
          .iter()
          .map(kv => "\{kv.0}=\{kv.1.stringify()}")
          .collect()
          .join(", ")
        let status = match (verdict.decision, approved) {
          (Allow, _) => green("allowed")
          (Deny(_), _) => red("DENIED")
          (Ask(_), Some(true)) => yellow("approved by user")
          (Ask(_), _) => red("NOT APPROVED")
        }
        println("  #\{id} \{bold(tool)}(\{shown})  \{status}")
        for c in verdict.concerns {
          let l = match arg_labels.get(c.culprit) {
            Some(l) => l
            None => c.label
          }
          println(dim("       \{c.culprit}: \{l.render()} — \{c.reason}"))
        }
      }
      Quarantined(id~, schema~, prompt_label~, answer~, ..) => {
        let a = match answer {
          Some(j) => j.stringify()
          None => "(not enough information)"
        }
        println("  #\{id} \{bold("query_ai_assistant")} -> \{schema} \{a}")
        println(
          dim(
            "       input labelled \{prompt_label.render()}; the answer inherits it",
          ),
        )
      }
      Print(text~, ..) => println("  " + dim("print: ") + text)
    }
  }
}

///|
/// Offline demo: the attack from AgentDojo's banking suite against the bill
/// payment task, with a quarantined LLM that the attacker fully controls.
fn demo() -> Unit {
  println(
    bold("Bactrian demo — paying a bill that contains a prompt injection\n"),
  )
  let task = @banking.user_tasks()[0]
  let inj = @banking.injection_tasks()[5]
  println("User:      \{task.prompt}")
  println("Attacker:  hides this in the bill → \"\{inj.goal}\"\n")
  let plan = @banking.reference_plan(task.id).unwrap()
  println(bold("Plan written by the planner (it never sees the bill):"))
  for line in plan.split("\n") {
    println("  " + dim(line.to_owned()))
  }
  println("")
  for round in 0..<2 {
    let bank = @banking.attacked_bank(task, inj)
    let pre = bank.snapshot()
    let world = if round == 0 {
      let permissive = @policy.Policy::new("none", [], unknown_tool=Allow)
      { ..@banking.world(), policy: permissive, }
    } else {
      @banking.world()
    }
    let host : @banking.BankHost = {
      bank,
      quarantined: (_, schema, _) => {
        let m : Map[String, Json] = Map([])
        for f in schema.fields {
          m[f.name] = match f.type_ {
            "float" => Json::number(1810.0)
            _ => Json::string(@banking.ATTACKER_IBAN)
          }
        }
        Quarantined(Answer(Json::object(m)))
      },
      approve: _ => false,
    }
    let title = if round == 0 {
      "Without a policy (a plain plan-then-execute agent):"
    } else {
      "With Bactrian's banking policy:"
    }
    println(bold(title))
    let (outcome, session) = @runtime.drive(world, host, plan)
    print_trace(session)
    let stolen = (inj.security)(pre, bank)
    match outcome {
      Failed(e) =>
        println("  outcome: \{e.kind().python_name()}: \{e.message()}")
      _ => println("  outcome: completed")
    }
    if stolen {
      println("  " + red("✗ the attacker received the money") + "\n")
    } else {
      println("  " + green("✓ no money reached the attacker") + "\n")
    }
  }
}

///|
fn check_policy(path : String) -> Unit {
  let text = @fs.read_file_to_string(path) catch {
    e => {
      println("cannot read \{path}: \{Repr(e)}")
      return
    }
  }
  let p = @policy.parse_policy(text) catch {
    PolicySyntaxError(line~, message~) => {
      println(red("\{path}:\{line}: \{message}"))
      return
    }
  }
  println(p.render())
  let problems = p.validate(@banking.world().signatures())
  if problems.is_empty() {
    println(green("✓ consistent with the banking tools"))
  } else {
    println(yellow("Against the banking tools:"))
    for pr in problems {
      println("  - \{pr}")
    }
  }
}

///|
fn run_plan_file(path : String) -> Unit {
  let plan = @fs.read_file_to_string(path) catch {
    e => {
      println("cannot read \{path}: \{Repr(e)}")
      return
    }
  }
  let bank = @banking.Bank::new()
  let host : @banking.BankHost = {
    bank,
    quarantined: (_, _, _) => Quarantined(NotEnoughInformation),
    approve: req => {
      println(
        yellow("approval requested for \{req.tool}: \{req.reason}") +
        " → refused",
      )
      false
    },
  }
  let (outcome, session) = @runtime.drive(@banking.world(), host, plan)
  print_trace(session)
  match outcome {
    Failed(e) => {
      println(red("failed: \{e.kind().python_name()}: \{e.message()}"))
      println(@agent.feedback(plan, e, @banking.policy()))
    }
    _ => println(green("completed"))
  }
}
