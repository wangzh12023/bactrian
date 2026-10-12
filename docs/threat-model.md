# Threat model

## What Bactrian protects

An agent acting for a **user** reads **data** that an **attacker** may have
written (documents, e-mails, web pages, messages, tool output). The attacker's
goal is to make the agent perform an action the user did not ask for, or to
send the user's data to someone who should not see it.

Under the assumptions below, Bactrian guarantees:

1. **Integrity of decisions.** Untrusted data never decides *which* side
   effect happens, *to whom*, or *whether* it happens, without the policy
   either refusing or asking the user. (Non-interference on the trusted
   projection of effects; checked by property tests.)
2. **Confidentiality of data.** Data reaches an audience chosen by data only if
   everyone in that audience may read it.
3. **No laundering through the quarantined model.** An answer of the
   quarantined LLM is labelled with everything in its prompt *and* with the
   model itself as an untrusted source: a hijacked model can produce *any*
   value — even when asked about trusted data — and that value is untrusted.
4. **No laundering through errors.** Error messages caused by untrusted data
   are not shown to the planner.
5. **At-most-once effects.** A retry never repeats an *identical* call: a call
   with the same tool and the same arguments is answered from the recorded
   result instead of being performed again. A corrected plan that changes an
   argument of an effect (say the subject of a transfer) performs a new,
   different effect, which the policy checks like any other.

## Assumptions

| Assumption | Why it is needed |
|---|---|
| The **planner** model sees only the user's request (and redacted errors) | Bactrian does not make the planner robust to injection; it keeps injected text away from it. |
| The **user's request** is not malicious | Bactrian protects the user, not third parties from the user. |
| **Tools label their output truthfully** (who wrote what, who may read it) and perform only their declared effect | The interpreter can only track what it is told. Mislabelled tools are the main deployment risk; policies make the labelling explicit and reviewable. |
| The **policy** is correct for the tools | `validate` catches references to unknown tools and arguments, not wrong intent. |
| The **user** reads confirmation requests | A user who approves everything can be phished like any user. Bactrian shows where each value came from to make the decision informed. |
| The host process is not compromised | Bactrian is an application-level reference monitor, not an OS sandbox. |

## Out of scope (explicit non-goals)

- **Misleading text shown to the user.** The agent may *print* attacker-written
  text ("your bill is 9 999 €"). Output is labelled, and a UI can mark it, but
  it is not suppressed.
- **Termination and timing channels.** Whether a program stops early (a policy
  denial, a `NotEnoughInformation` from the quarantined model) depends on data
  and reveals about one bit per attempt. Programs are not constant-time.
- **Tasks that *are* following instructions in data** ("do what this e-mail
  says"). They require untrusted data to decide actions and are refused or held
  for approval by design.
- **Denial of service.** An attacker can make a task fail (e.g. by making the
  quarantined model refuse); they cannot make it do something else.
- **Multi-agent delegation** and agents that write programs for other agents.
- **Side channels in tools themselves** (a tool that leaks its arguments).

## Compared with detection

Detectors (classifiers, "guardrail" prompts, LLM judges) estimate whether text
is an attack. Adaptive attacks optimise against them; in *The Attacker Moves
Second* (Nasr et al., 2025) most published detection and training-based defences
were bypassed with high success rates. Bactrian makes no such estimate: the
injected text may be perfectly persuasive, and it still cannot reach the
decision. The cost is utility — some legitimate tasks need the user's approval
or fail (see [evaluation.md](evaluation.md)).

## Known differences from CaMeL

Bactrian follows CaMeL's architecture. Reading CaMeL's reference code (Apache-2.0,
a research artefact) suggested several issues that Bactrian addresses and tests:

- container elements keep their own labels through builtins (no reset to
  "trusted, public");
- implicit flows through skipped branches are tracked (variables a branch *may*
  write are tainted whichever branch runs);
- recipients/payees chosen by data cannot receive data they may not read, even
  if the body is "public";
- denial messages and error feedback do not contain the private values that
  caused them;
- policies are data with tests, not untested Python callbacks;
- an *identical* call is not performed twice when the planner retries (a call
  whose arguments changed is a new effect, checked like any other).
