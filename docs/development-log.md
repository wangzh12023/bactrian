# Development log and use of AI

The hackathon rules ask that the participant understands and is responsible
for every part of the project, and that the use of AI is explained. This file
does both.

## How AI was used

The project was developed with an AI coding assistant (Claude) acting as pair
programmer under the participant's direction, and with LLMs as *components*
of the system under test.

| Activity | Role of AI | How correctness was established |
|---|---|---|
| Market and literature research (CaMeL, FIDES, AgentDojo, MoonBit ecosystem, past winners) | Searching, reading and summarising repositories, papers and registries | Claims were checked against the sources (reports in the project's research notes); the decision record lists what was verified first-hand |
| Design (lattice, label rules, sans-IO effects, policy language) | Proposing and discussing designs | Every rule is covered by a test; the non-interference property is the arbiter |
| Code | Writing MoonBit code with the compiler as the first reviewer (`moon check`), then tests | 38 test blocks incl. QuickCheck properties; CI on Linux and Windows, wasm and JS |
| Debugging | Interpreting failing property tests and benchmark runs | Two real security bugs were found this way (see below) |
| As components | The planner and the quarantined LLM are real models (DeepSeek, Qwen, GPT-4o-mini via an OpenAI-compatible gateway) | The security argument does not depend on them: tests replace the quarantined model with an adversary |

What AI was **not** used for: the security guarantees are not "checked by an
LLM". They follow from the interpreter's label rules and are tested
deterministically.

## Timeline

- **2026-10-12** — Research: hackathon rules, MoonBit toolchain (verified
  hands-on: async HTTPS on wasm and JS, JS exports), 2,952 mooncakes modules
  and 1,049 recent repositories scanned for overlap; CaMeL and AgentDojo read
  in full. Decision: a CaMeL-style runtime is the one AI-application niche that
  is open both in the MoonBit ecosystem and globally.
- Security labels (`label/`) with lattice-law properties.
- Policy model, checker, parser and renderer (`policy/`).
- Labelled interpreter on top of pure-py's parser (`runtime/`): values,
  operators, builtins, methods, comprehensions, records, tool calls,
  quarantined calls, STRICT control-flow labels.
- Redesign to sans-IO effects with deterministic replay, so that the same core
  serves CLI, browser and tests, and retries never repeat side effects.
- Non-interference property test — **found a bug**: a write to an existing
  dictionary key did not record the key's label in the dictionary's shape.
  Fixed: keyed writes always join the key into the shape; reads by key depend
  on the shape.
- Agent loop with redacted feedback; AgentDojo banking suite ported (16 user
  tasks, 9 injection tasks, MIT); 0/144 attacks succeed with a hijacked
  quarantined model; with an allow-all policy the same plans are exploited.
- OpenAI-compatible client, benchmark harness, undefended tool-calling
  baseline, CLI; first end-to-end runs with real models.
- Real-model runs drove changes to the planner prompt: models asked the
  quarantined LLM for derived values ("the new rent") that it correctly
  refused to guess; the prompt now asks for stated facts only and computes the
  rest, and a trusted `get_current_date` tool replaces assumed dates.
- Browser playground (rabbita, compiled to JS) with four scenarios.
- Benchmark with a hijacked quarantined LLM and a real planner — **found a
  bug**: when the planner asked the assistant to *select* a payee from trusted
  data, the answer inherited only its prompt's label and was trusted.
  Fixed: the assistant's answers always carry an untrusted source.
- CI (Linux and Windows; wasm and JS), GitHub Pages deployment, docs.

## Design decisions worth explaining

- **Why a Python subset?** Models write Python best; CaMeL showed planners can
  express tasks in it. Using an existing CPython-shaped parser (pure-py) kept
  the effort on the security semantics.
- **Why STRICT labels by default?** CaMeL's own evaluation shows NORMAL mode
  leaks through branches. Bactrian additionally taints variables a *skipped*
  branch could have written — the classic hole of purely dynamic IFC.
- **Why `confirm` rather than `require` for payees?** Paying a bill to the
  account printed on it is a legitimate task. Refusing it would make the agent
  useless; allowing it silently would make it exploitable. Asking, with the
  provenance shown, makes it a human decision.
- **Why does a denial end the task?** Letting the planner "try another way"
  after a denial invites it to route around the policy.
- **Why sans-IO?** It made the browser playground, adversarial tests and
  at-most-once retries fall out of one design instead of three.
