# Bactrian 🐫🐫

**A prompt-injection-proof runtime for AI agents, written in MoonBit.**

Bactrian runs the plans that a language model writes for an agent inside an
interpreter that tracks *where every value came from* and *who may read it*.
Before every tool call a declarative policy decides — deterministically — whether
the call may happen. Untrusted data (e-mails, web pages, files, tool output) can
never decide *what* the agent does, only fill in the blanks the user asked for.

> Work in progress for the 2026 MoonBit Hackathon (AI application track).

## Status

- [x] security labels (sources × readers lattice) with property tests
- [x] policy engine + policy file language (parse / render / validate)
- [x] labelled interpreter for a Python subset (STRICT control-flow labels)
- [ ] planner / quarantined LLM loop
- [ ] AgentDojo-derived benchmark suites
- [ ] CLI and browser playground

## License

Apache-2.0. Design inspired by CaMeL ("Defeating Prompt Injections by Design",
Debenedetti et al., 2025); see `NOTICE` for attributions.
