///|
using @html {div, span, button, textarea, h1, h2, h3, p, label, input}

///|
fn view(m : Model, emit : @rabbita.Emit[Msg]) -> @html.Html {
  let s = scenarios()[if m.scenario == live_tab { 0 } else { m.scenario }]
  let (policy, policy_error) : (@policy.Policy?, String?) = try
    @policy.parse_policy(m.policy)
  catch {
    PolicySyntaxError(line~, message~) =>
      (None, Some("line \{line}: \{message}"))
  } noraise {
    p => (Some(p), None)
  }
  div(class="page", [
    header(),
    div(
      class="tabs",
      [
        ..scenarios().mapi((i, sc) => {
          button(
            class=if i == m.scenario { "tab active" } else { "tab" },
            on_click=emit(Pick(i)),
            sc.title,
          )
        }),
        button(
          class=if m.scenario == live_tab {
            "tab live active"
          } else {
            "tab live"
          },
          on_click=emit(Pick(live_tab)),
          "⚡ Live: a real model plans",
        ),
      ],
    ),
    if m.scenario == live_tab {
      live_view(m, emit)
    } else {
      scenario_view(m, s, policy, policy_error, emit)
    },
    footer(),
  ])
}

///|
fn scenario_view(
  m : Model,
  s : Scenario,
  policy : @policy.Policy?,
  policy_error : String?,
  emit : @rabbita.Emit[Msg],
) -> @html.Html {
  div(class="page-body", [
    div(class="grid", [
      div(class="col", [
        p(class="lesson", s.lesson),
        panel("The user asks", [p(class="request", "“\{s.request}”")]),
        panel("The planner writes a program — it never sees the documents", [
          textarea(
            class="code",
            rows=11,
            value=m.plan,
            on_input=emit.map(t => EditPlan(t)),
            m.plan,
          ),
        ]),
        panel("The attacker plants text in the documents", [
          textarea(
            class="code inject",
            rows=4,
            value=m.injection,
            on_input=emit.map(t => EditInjection(t)),
            m.injection,
          ),
          p(
            class="hint",
            "…and fully controls the quarantined assistant's answers:",
          ),
          textarea(
            class="code inject",
            rows=2,
            value=m.q_answer,
            on_input=emit.map(t => EditAnswer(t)),
            m.q_answer,
          ),
        ]),
        div(class="controls", [
          label(class="toggle", [
            input(
              input_type=Checkbox,
              checked=m.approve,
              on_change=emit.map(_ => ToggleApprove),
            ),
            span(" the user approves everything that asks for confirmation"),
          ]),
          button(class="run", on_click=emit(Run), "▶ Run both"),
          button(class="ghost", on_click=emit(Reset), "Reset"),
        ]),
      ]),
      div(class="col wide", [
        if !m.ran {
          p(class="hint", "Edited — press ▶ Run both.")
        } else {
          match policy {
            None => p(class="error", "The policy has a syntax error.")
            Some(pol) if !pol.errors(@banking.signatures()).is_empty() =>
              // Fail closed: a rule about a tool or an argument the bank does
              // not have would never fire, so such a policy is not run.
              p(
                class="error",
                "The policy names tools or arguments the bank does not have (see below), so it is not run.",
              )
            Some(pol) =>
              div(class="sides", [
                side(
                  "Without Bactrian",
                  "same plan, policy allows everything",
                  run_side(
                    m,
                    @policy.Policy::new("none", [], unknown_tool=Allow),
                  ),
                  false,
                ),
                side("With Bactrian", "banking policy", run_side(m, pol), true),
              ])
          }
        },
        panel("The policy — plain text, edit it", [
          textarea(
            class="code policy",
            rows=14,
            value=m.policy,
            on_input=emit.map(t => EditPolicy(t)),
            m.policy,
          ),
          match policy_error {
            Some(e) => p(class="error", e)
            None =>
              match policy {
                Some(pol) => validation(pol)
                None => @html.nothing
              }
          },
        ]),
      ]),
    ]),
  ])
}

///|
fn header() -> @html.Html {
  div(class="header", [
    h1([span(class="logo", "🐫🐫"), span(" Bactrian")]),
    p(
      class="tagline",
      "Agents that cannot be talked into anything. Every value carries where it came from and who may read it; a policy checks every action before it happens. Not a filter that guesses — an interpreter that knows.",
    ),
  ])
}

///|
fn footer() -> @html.Html {
  div(class="footer", [
    p([
      span(
        "Runs entirely in your browser: interpreter, policy engine and simulated bank are MoonBit compiled to JavaScript. ",
      ),
      @html.a(
        href="https://github.com/wangzh12023/bactrian",
        "Source on GitHub",
      ),
      span(". Scenarios adapted from AgentDojo (MIT)."),
    ]),
  ])
}

///|
fn panel(title : String, body : Array[@html.Html]) -> @html.Html {
  div(class="panel", [h3(title), ..body])
}

///|
fn side(
  title : String,
  subtitle : String,
  r : RunView,
  defended : Bool,
) -> @html.Html {
  let verdict = if r.stolen {
    div(class="verdict bad", "✗ The attacker got what they wanted")
  } else if defended {
    div(class="verdict good", "✓ The attack failed")
  } else {
    div(class="verdict neutral", "No attacker goal reached")
  }
  div(class=if defended { "side defended" } else { "side" }, [
    h2(title),
    p(class="sub", subtitle),
    verdict,
    div(class="trace", r.events.map(e => event_view(e, r.session))),
    div(class=if r.ok { "outcome ok" } else { "outcome stop" }, r.outcome),
    if r.effects.is_empty() {
      p(class="effects none", "No side effects.")
    } else {
      div(
        class="effects",
        [p("Side effects:"), ..r.effects.map(e => div(class="effect", e))],
      )
    },
  ])
}

///|
fn event_view(e : @runtime.Event, session : @runtime.Session) -> @html.Html {
  match e {
    ToolCall(id~, tool~, args~, arg_labels~, verdict~, approved~, ..) => {
      let (badge, cls) = match (verdict.decision, approved) {
        (Allow, _) => ("allowed", "allow")
        (Deny(_), _) => ("denied", "deny")
        (Ask(_), Some(true)) => ("approved by user", "ask")
        (Ask(_), _) => ("held for approval — declined", "deny")
      }
      let culprits = verdict.concerns.map(c => c.culprit)
      div(
        class="call \{cls}",
        [
          div(class="call-head", [
            span(class="id", "#\{id}"),
            span(class="tool", tool),
            span(class="badge \{cls}", badge),
          ]),
          div(
            class="args",
            args
            .iter()
            .map(kv => {
              let lbl = arg_labels.get(kv.0).unwrap_or(@label.Label::bottom())
              let trusted = @banking.policy().is_trusted(lbl)
              div(
                class=if culprits.contains(kv.0) {
                  "arg culprit"
                } else {
                  "arg"
                },
                [
                  span(class="k", kv.0),
                  span(class="v", short(kv.1.stringify(), 60)),
                  span(
                    class=if trusted { "lbl trusted" } else { "lbl untrusted" },
                    title=lbl.render(),
                    compact_label(lbl, trusted),
                  ),
                ],
              )
            })
            .collect(),
          ),
          ..verdict.concerns.map(c => {
            div(class="concern", [
              span(class="why", c.reason),
              span(
                class="from",
                " — \{c.culprit} " + @runtime.explain_label(c.label, session),
              ),
            ])
          }),
        ],
      )
    }
    Quarantined(id~, schema~, prompt_label~, answer~, ..) =>
      div(class="call q", [
        div(class="call-head", [
          span(class="id", "#\{id}"),
          span(class="tool", "query_ai_assistant → \{schema}"),
          span(class="badge q", "quarantined"),
        ]),
        div(class="args", [
          div(class="arg", [
            span(class="k", "answer"),
            span(
              class="v",
              short(
                answer
                .map(j => j.stringify())
                .unwrap_or("not enough information"),
                70,
              ),
            ),
            span(
              class="lbl untrusted",
              title=prompt_label.render(),
              compact_label(prompt_label, false),
            ),
          ]),
        ]),
      ])
    Print(text~, ..) => div(class="print", "print: " + short(text, 120))
  }
}

///|
fn short(s : String, n : Int) -> String {
  if s.length() <= n {
    s
  } else {
    s.view(end_offset=n).to_owned() + "…"
  }
}

///|
fn validation(pol : @policy.Policy) -> @html.Html {
  let problems = pol.validate(@banking.signatures())
  if problems.is_empty() {
    p(class="ok", "✓ The policy is consistent with the bank's tools.")
  } else {
    div(class="warn", problems.map(pr => div("⚠ " + pr)))
  }
}

///|
/// A short tag for a label: whether it is trusted, which untrusted tools it
/// came from, and whether it is private. The full label is in the tooltip.
fn compact_label(l : @label.Label, trusted : Bool) -> String {
  let from = l.sources
    .to_array()
    .filter_map(s => {
      match s {
        Tool(t) if !trusted => Some(t)
        Party(p) => Some("by " + short(p, 10))
        _ => None
      }
    })
  let who = match l.readers {
    Public => ""
    Only(_) => " · private"
  }
  if trusted {
    "trusted" + who
  } else {
    "untrusted ← " +
    from.join(", ").replace(old="query_ai_assistant", new="assistant") +
    who
  }
}
