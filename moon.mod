name = "wangzh12023/bactrian"

version = "0.1.0"

readme = "README.md"

repository = "https://github.com/wangzh12023/bactrian"

license = "Apache-2.0"

keywords = [
  "agent",
  "security",
  "prompt-injection",
  "information-flow",
  "llm",
  "camel",
]

description = "Prompt-injection-proof agent runtime: a capability-tracking interpreter for LLM-written plans (CaMeL-style IFC) in MoonBit"

preferred_target = "wasm"

import {
  "marianoguerra/pure-py@0.10.0",
  "moonbitlang/async@0.22.4",
  "moonbitlang/x@0.5.5",
  "moonbit-community/rabbita@0.16.4",
}
