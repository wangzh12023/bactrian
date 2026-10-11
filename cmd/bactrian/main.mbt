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
    #|  bactrian run "<request>" [--attack N] run a banking request with a real model
    #|  bactrian bench [--tasks a,b] [--injections a,b] [--baseline] [--hijack]
    #|                                        run the AgentDojo-derived banking benchmark
    #|  bactrian policy <file>                check a policy file and print it back
    #|  bactrian plan <file.py>               run a plan against the banking suite offline
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
      let attack = match flag_value(more.to_owned(), "--attack") {
        Some(s) => Some(@string.parse_int(s) catch { _ => -1 })
        None => None
      }
      run_request(request, attack)
    }
    ["bench", .. more] => bench(more.to_owned())
    ["policy", path, ..] => check_policy(path)
    ["plan", path, ..] => run_plan_file(path)
    _ => println(usage())
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
