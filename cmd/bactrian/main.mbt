///|
/// `bactrian`: run tasks, benchmarks and policy checks from the command line.
///
/// Configuration comes from the environment so keys never appear in shell
/// history or files:
///
/// - `BACTRIAN_BASE_URL` — OpenAI-compatible base URL (falls back to
///   `OPENAI_BASE_URL`), e.g. `https://qianfan.baidubce.com/v2`
/// - `BACTRIAN_API_KEY` — API key (falls back to `OPENAI_API_KEY`)
/// - `BACTRIAN_MODEL` — model of the planner (default `deepseek-chat`)
/// - `BACTRIAN_Q_MODEL` — model of the quarantined LLM (default: same)

///|
fn env_or(names : Array[String], default : String) -> String {
  for n in names {
    match @env.get_env_var(n) {
      Some(v) if v != "" => return v
      _ => ()
    }
  }
  default
}

///|
fn endpoints() -> (@llm.Endpoint, @llm.Endpoint) {
  let base = env_or(
    ["BACTRIAN_BASE_URL", "OPENAI_BASE_URL"],
    "https://api.deepseek.com",
  )
  let key = env_or(
    ["BACTRIAN_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"],
    "",
  )
  let model = env_or(["BACTRIAN_MODEL"], "deepseek-chat")
  let q_model = env_or(["BACTRIAN_Q_MODEL"], model)
  (
    @llm.Endpoint::new(base, key, model),
    @llm.Endpoint::new(base, key, q_model, max_tokens=1024),
  )
}

///|
fn usage() -> String {
  (
    #|bactrian — a prompt-injection-proof runtime for AI agents
    #|
    #|USAGE
    #|  bactrian demo                         replay the bill-payment attack offline
    #|  bactrian run "<request>" [--attack N] [--approve]
    #|                                        run a banking request with a real model
    #|  bactrian bench [--tasks a,b] [--injections a,b] [--baseline] [--hijack] [--verbose]
    #|                                        run the AgentDojo-derived banking benchmark
    #|  bactrian policy <file>                parse a policy file, print it back and check
    #|                                        it against the banking tools
    #|  bactrian plan <file.py> [--attack N] [--hijack] [--approve]
    #|                                        run a plan you wrote against the simulated
    #|                                        bank, offline (no model, no key)
    #|
    #|OPTIONS
    #|  --attack N   plant AgentDojo banking injection task N (0-8) in every document
    #|  --approve    approve every confirmation request (each is printed with the
    #|               reason and where the data came from); by default the CLI declines
    #|  --hijack     plan: the attacker answers every query_ai_assistant call;
    #|               bench: the same, instead of the quarantined model
    #|               (plan without --hijack: the assistant always answers
    #|               "not enough information")
    #|
    #|EXIT STATUS
    #|  0 on success; 1 when a policy file cannot be read, has a syntax error or
    #|  names tools or arguments the banking tools do not have, when a plan file
    #|  cannot be read, when no API key is set for run/bench, or on bad usage
    #|
    #|ENVIRONMENT
    #|  BACTRIAN_BASE_URL  OpenAI-compatible base URL (e.g. https://qianfan.baidubce.com/v2)
    #|  BACTRIAN_API_KEY   API key
    #|  BACTRIAN_MODEL     planner model (default deepseek-chat)
    #|  BACTRIAN_Q_MODEL   quarantined model (default: same as planner)
  )
}

///|
async fn main {
  let args = @env.args()
  // Under moonrun the first argument is the program; under Node the first two.
  let start = match
    args.search_by(a => {
      a
      is ("demo"
      | "run"
      | "bench"
      | "policy"
      | "plan"
      | "help"
      | "--help"
      | "-h")
    }) {
    Some(i) => i
    None => args.length()
  }
  let rest = args[start:].to_owned()
  match rest {
    ["demo", ..] => demo()
    ["run", request, .. more] => {
      let more = more.to_owned()
      run_request(request, attack_flag(more), approve=flag(more, "--approve"))
    }
    ["bench", .. more] => bench(more.to_owned())
    ["policy", path, ..] => check_policy(path)
    ["plan", path, .. more] => {
      let more = more.to_owned()
      run_plan_file(
        path,
        attack_flag(more),
        hijack=flag(more, "--hijack"),
        approve=flag(more, "--approve"),
      )
    }
    ["help" | "--help" | "-h", ..] => println(usage())
    _ => {
      println(usage())
      exit(1)
    }
  }
}

///|
/// Ends the program with `code`. Errors are reported on standard output
/// before calling this, like the rest of the CLI's output.
fn exit(code : Int) -> Unit {
  @sys.exit(code)
}

///|
/// The `--attack N` option: `None` without it. An `N` that names no
/// injection task is reported and ends the program.
fn attack_flag(args : Array[String]) -> Int? {
  match flag_value(args, "--attack") {
    None => None
    Some(s) => {
      let n = @banking.injection_tasks().length()
      let i = @string.parse_int(s) catch { _ => -1 }
      if i >= 0 && i < n {
        Some(i)
      } else {
        println("--attack expects an injection task between 0 and \{n - 1}")
        exit(1)
        None
      }
    }
  }
}

///|
fn flag_value(args : Array[String], name : String) -> String? {
  for i, a in args {
    if a == name {
      return args.get(i + 1)
    }
  }
  None
}

///|
fn flag(args : Array[String], name : String) -> Bool {
  args.contains(name)
}
