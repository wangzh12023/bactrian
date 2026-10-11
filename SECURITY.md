# Security policy

Bactrian is a security tool, so holes in it matter. Thank you for looking.

## What counts as a vulnerability

Anything that breaks a guarantee in [docs/threat-model.md](docs/threat-model.md)
under its stated assumptions, for example:

- a plan and two worlds that differ only in untrusted data (tool output whose
  source is untrusted, or answers of the quarantined model) in which the side
  effects the policy allows *without asking* differ — other than one world
  stopping earlier;
- a value labelled trusted whose content depends on untrusted data;
- data reaching an audience chosen by data that may not read it;
- an error message derived from untrusted data reaching the planner;
- a side effect performed twice within one task.

Out-of-scope behaviour is listed in the threat model (misleading text shown to
the user, termination channels, mislabelled tools, a user who approves
everything).

## How to report

Open a GitHub issue with the label `security` containing the plan, the two
worlds (or the tool results), the expected and the actual behaviour. If the
hole is severe and you prefer not to disclose it publicly first, open an issue
asking for a private contact and do not include details.

The fastest way to demonstrate a hole is a test in
`runtime/noninterference_test.mbt`: add the plan to `plans` and run
`moon test runtime`; the property prints a counterexample.

## How holes are handled

Every confirmed hole gets a fix, a regression test, and an entry in
[docs/evaluation.md](docs/evaluation.md) under "Bugs these tests found". The
bugs found so far are listed there.
