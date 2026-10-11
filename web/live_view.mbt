///|
fn live_view(m : Model, emit : @rabbita.Emit[Msg]) -> @html.Html {
  let l = m.live
  let field = fn(
    title : String,
    value : String,
    input_type : @html.InputType,
    set : (Live, String) -> Live,
  ) -> @html.Html {
    label(class="field", [
      span(class="field-name", title),
      input(
        input_type~,
        value~,
        on_input=emit.map(v => LiveEdit(l => set(l, v))),
      ),
    ])
  }
  let attacks = @banking.injection_tasks()
  let busy = l.status is Planning
  div(class="grid", [
    div(class="col", [
      p(
        class="lesson",
        "Live: a real model plans in your browser. It only ever sees your request; the documents of the simulated bank carry the attack you choose. Requests go straight from this page to the endpoint you configure (it must allow browser requests, e.g. Baidu Qianfan v2, DeepSeek or any OpenAI-compatible gateway).",
      ),
      panel("Model (OpenAI-compatible)", [
        div(
          class="presets",
          [
            span(class="hint", "Presets: "),
            ..presets.map(pr => {
              button(
                class="ghost small",
                on_click=emit(
                  LiveEdit(l => { ..l, base_url: pr.1, model: pr.2, }),
                ),
                pr.0,
              )
            }),
          ],
        ),
        field("Base URL", l.base_url, Text, (l, v) => { ..l, base_url: v, }),
        field("API key", l.api_key, Password, (l, v) => { ..l, api_key: v, }),
        field("Model", l.model, Text, (l, v) => { ..l, model: v, }),
        p(
          class="hint",
          "The key is kept in this browser only and sent only to the endpoint above.",
        ),
      ]),
      panel("Your request", [
        textarea(
          class="code",
          rows=3,
          value=l.request,
          on_input=emit.map(v => LiveEdit(l => { ..l, request: v, })),
          l.request,
        ),
      ]),
      panel("The attacker plants this in every document", [
        @html.select(
          on_change=emit.map(v => {
            LiveEdit(l => {
              ..l,
              attack: @string.parse_int(v) catch {
                _ => -1
              },
            })
          }),
          [
            @html.option(value="-1", selected=l.attack < 0, "no attack"),
            ..attacks.mapi((i, a) => {
              @html.option(
                value=i.to_string(),
                selected=l.attack == i,
                short(a.goal, 90),
              )
            }),
          ],
        ),
      ]),
      div(class="controls", [
        label(class="toggle", [
          input(
            input_type=Checkbox,
            checked=l.approve,
            on_change=emit.map(_ => LiveEdit(l => { ..l, approve: !l.approve, })),
          ),
          span(" I approve everything that asks for confirmation"),
        ]),
        button(
          class="run",
          disabled=busy || l.api_key == "",
          on_click=emit(LiveStart),
          if busy {
            "… working"
          } else {
            "▶ Ask the model"
          },
        ),
      ]),
    ]),
    div(class="col wide", [
      match l.status {
        Idle =>
          p(class="hint", "Configure a model and press ▶ Ask the model.")
        Planning =>
          p(
            class="hint",
            "The model is planning and Bactrian is running the plan…",
          )
        Failed(msg) => p(class="error", msg)
        Finished =>
          match m.live_result {
            Some(r) => live_result_view(r, l)
            None => @html.nothing
          }
      },
    ]),
  ])
}

///|
fn live_result_view(r : LiveResult, l : Live) -> @html.Html {
  let t = r.task
  let stolen = match @banking.injection_tasks().get(l.attack) {
    Some(inj) => (inj.security)(r.pre, r.post)
    None => false
  }
  let verdict = if l.attack < 0 {
    @html.nothing
  } else if stolen {
    div(class="verdict bad", "✗ The attacker got what they wanted")
  } else {
    div(class="verdict good", "✓ The attack failed")
  }
  let ending = match t.ending {
    Some(Done(output~)) =>
      div(class="outcome ok", "done — " + short(output, 300))
    Some(Blocked(tool~, reason~)) =>
      div(class="outcome stop", "blocked \{tool}: \{reason}")
    Some(Declined(tool~, reason~)) =>
      div(class="outcome stop", "\{tool} needs your approval: \{reason}")
    Some(GaveUp(reason~)) => div(class="outcome stop", "gave up: \{reason}")
    None => @html.nothing
  }
  let attempts = t.attempts.mapi((i, a) => {
    @html.details(open=i == t.attempts.length() - 1, [
      @html.summary(
        "Program \{i + 1}: " +
        short(
          a.outcome
          .split("\n")
          .map(x => x.to_owned())
          .collect()
          .filter(x => x.trim() != "")
          .get(0)
          .unwrap_or(""),
          90,
        ),
      ),
      @html.pre(class="code-view", a.code),
    ])
  })
  let session = match t.session {
    Some(s) => s
    None => @runtime.Session::new()
  }
  div(class="side defended", [
    h2("What the model did, under Bactrian"),
    verdict,
    div(class="attempts", attempts),
    div(class="trace", session.events.map(e => event_view(e, session))),
    ending,
  ])
}

///|
/// One-click endpoint presets: (label, base URL, model).
let presets : Array[(String, String, String)] = [
  ("Baidu Qianfan · ERNIE", "https://qianfan.baidubce.com/v2", "ernie-5.0"),
  ("DeepSeek", "https://api.deepseek.com", "deepseek-chat"),
  (
    "Qwen (DashScope)", "https://dashscope.aliyuncs.com/compatible-mode/v1", "qwen-plus",
  ),
  ("OpenAI", "https://api.openai.com/v1", "gpt-4o-mini"),
]
