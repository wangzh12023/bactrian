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
      // The undefended run: a policy that names no tool and allows all.
      let permissive = @policy.Policy::new("none", [], unknown_tool=Allow)
      @banking.world_with(policy=permissive) catch {
        InconsistentPolicy(errors) => abort(errors.join("; "))
      }
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
/// Parses a policy file, prints it back in canonical form and checks it
/// against the banking tools. Exits with 1 when the file cannot be read, has
/// a syntax error, or names tools or arguments the bank does not have (such a
/// rule would never fire). Banking tools the policy does not mention are
/// only reported: their calls are denied by default.
fn check_policy(path : String) -> Unit {
  let text = @fs.read_file_to_string(path) catch {
    IOError(msg) => {
      println(red("cannot read \{path}: \{msg}"))
      exit(1)
      return
    }
  }
  let p = @policy.parse_policy(text) catch {
    PolicySyntaxError(line~, message~) => {
      println(red("\{path}:\{line}: \{message}"))
      exit(1)
      return
    }
  }
  println(p.render())
  let signatures = @banking.signatures()
  let errors = p.errors(signatures)
  let gaps = p.validate(signatures).filter(pr => !errors.contains(pr))
  if errors.is_empty() && gaps.is_empty() {
    println(green("✓ consistent with the banking tools"))
  }
  if !gaps.is_empty() {
    println(yellow("Against the banking tools:"))
    for pr in gaps {
      println("  - \{pr}")
    }
  }
  if !errors.is_empty() {
    println(
      red(
        "✗ refused: these name tools or arguments the banking tools do not have, so the rules would never fire:",
      ),
    )
    for pr in errors {
      println("  - \{pr}")
    }
    exit(1)
  }
}

///|
/// Prints a confirmation request — what needs approval, why, and where the
/// offending data came from — and the decision.
fn print_confirmation(req : @runtime.ConfirmRequest, approve : Bool) -> Unit {
  println(yellow("Approval needed for \{req.tool}: \{req.reason}"))
  let args = req.args
    .iter()
    .map(kv => "\{kv.0}=\{kv.1.stringify()}")
    .collect()
    .join(", ")
  println("  call: \{req.tool}(\{args})")
  for p in req.provenance {
    println("  \{p.0} \{p.1}")
  }
  if approve {
    println(yellow("  → approved (--approve)"))
  } else {
    println(dim("  → declined (pass --approve to approve)"))
  }
}

///|
/// Runs a plan written by hand against the simulated bank, offline. With
/// `attack`, the documents carry that injection task; with `hijack`, the
/// attacker answers every `query_ai_assistant` call (otherwise the assistant
/// answers "not enough information"). Confirmation requests are declined
/// unless `approve`. Exits with 1 when the file cannot be read.
fn run_plan_file(
  path : String,
  attack : Int?,
  hijack? : Bool = false,
  approve? : Bool = false,
) -> Unit {
  let plan = @fs.read_file_to_string(path) catch {
    IOError(msg) => {
      println(red("cannot read \{path}: \{msg}"))
      exit(1)
      return
    }
  }
  let injection = attack.bind(i => @banking.injection_tasks().get(i))
  let bank = match injection {
    Some(inj) => {
      println(yellow("injected into every document: ") + inj.goal)
      @banking.attacked_bank(
        {
          id: "plan",
          prompt: "",
          vectors: @banking.Vector::all(),
          utility: (_, _, _) => true,
        },
        inj,
      )
    }
    None => @banking.Bank::new()
  }
  let pre = bank.snapshot()
  let host : @banking.BankHost = {
    bank,
    quarantined: (_, schema, _) => {
      if hijack {
        Quarantined(@bench.hijacked_answer(schema))
      } else {
        Quarantined(NotEnoughInformation)
      }
    },
    approve: req => {
      print_confirmation(req, approve)
      approve
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
  if injection is Some(inj) {
    if (inj.security)(pre, bank) {
      println(red("✗ the attacker's goal was reached"))
    } else {
      println(green("✓ the attacker's goal was not reached"))
    }
  }
}
