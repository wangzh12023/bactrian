# Contributing

## Setup

Install the [MoonBit toolchain](https://www.moonbitlang.com/download/)
(tested with `moonc 0.10.14`), then:

```console
$ git config core.hooksPath .githooks   # deny warnings before every commit
$ moon test                             # wasm (default target)
$ moon test --target js
```

## Where things live

| Package | Responsibility | Depends on |
|---|---|---|
| `label/` | the security lattice | core only |
| `policy/` | policy model, checker, file language | `label` |
| `runtime/` | labelled interpreter, effects, replay | `label`, `policy`, pure-py |
| `agent/` | planner prompt, task loop, feedback | `runtime`, `policy` |
| `llm/` | OpenAI-compatible client | `agent`, `runtime`, async |
| `suites/*` | simulated environments, tasks, policies | `runtime` |
| `bench/` | benchmark harness, baseline agent | `llm`, `suites/banking` |
| `cmd/bactrian/` | CLI | everything |
| `web/` | playground (JS only) | `runtime`, `suites/banking`, rabbita |

Only `llm`, `bench`, `cmd/bactrian` and `web` perform I/O. Keep it that way:
the interpreter must stay a pure function of the plan, the world and the memo.

## Rules for changes to the interpreter

Every operation in `runtime/` must say where its result's label comes from.
When you add one:

1. Write the label rule in a comment next to the code.
2. Add a plan that uses it to `plans` in `runtime/noninterference_test.mbt`
   — preferably one that would break if the rule were wrong — and run
   `moon test runtime`.
3. If the operation writes to variables or containers, make sure
   `runtime/flow.mbt` (`may_write`, `expr_writes`, `target_roots`) sees the
   write; otherwise implicit flows through skipped branches are lost.

## Adding a suite

Copy `suites/mail/`: describe the tools (`ToolSpec`) and the types they return,
implement the tools so that each result says who wrote which part and who may
read it (`ToolResult.paths`), write a policy file, and add tests that run plans
against a hijacked quarantined model. `Policy::validate` must report no
problems for your tools.

## Style

`moon fmt` before committing, `moon info` when public APIs change (the
generated `pkg.generated.mbti` files are committed and checked in CI). Commit
messages explain *why*.
