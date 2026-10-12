# The policy language

A policy is a text file. One directive per line; `#` starts a comment; rules
are indented under their `effect`.

```text
policy "banking"
self "me", "DE89370400440532013000"
trust tools get_balance, get_iban, get_user_info
trust parties "landlord@example.com"
context confirm

read get_iban, get_balance, read_file

effect send_money audience recipient
  confirm trusted(recipient) : "the payee was not chosen by you: it comes from data"
  confirm at_most(amount, 1000) : "transfers above 1000 need your approval"

effect update_password
  require trusted(password) : "a new password must come from you"
```

## Directives

| directive | meaning |
|---|---|
| `policy "name"` | the policy's name |
| `self "id", …` | identifiers of the user (accounts, addresses). The user may read everything, is trusted as a party, and is never counted as an audience. |
| `trust tools a, b` | tools whose output is trusted (systems of record). Parts of their output authored by an untrusted `Party` are still untrusted. |
| `trust parties "x", …` | external authors whose content is trusted |
| `context require \| confirm \| ignore` | what to do with an effect whose execution was decided by untrusted data (a branch condition, a loop over untrusted data) |
| `unknown allow \| confirm \| deny` | decision for tools without an entry (default `deny`: fail closed) |
| `read a, b` | tools without side effects; always allowed |
| `effect t [audience a, b]` | a tool with side effects; `audience` names the arguments that say who observes the effect |
| `  require COND : "reason"` | deny the call when `COND` fails |
| `  confirm COND : "reason"` | ask the user when `COND` fails |

## Conditions

| condition | holds when |
|---|---|
| `trusted(arg)` | every source of the argument's value (deeply) is trusted |
| `public(arg)` | anyone may read the argument |
| `readable_by(arg, ["p", …])` | all listed principals may read it |
| `context_trusted` | no untrusted data decided whether this call happens |
| `at_most(arg, n)` | the argument is a number ≤ `n` |
| `one_of(arg, [lit, …])` | the argument equals one of the literals |
| `present(arg)` | the argument is given and not `None` |
| `all(c, …)`, `any(c, …)`, `not(c)` | combinators |

## Built-in checks

For every `effect` with an `audience`, before its rules: if any audience
argument is untrusted (data chose the recipient), then every other argument and
the call's context must be readable by everyone in the audience — otherwise the
call is **denied**. This is what stops "send the user's transaction history to
the attacker" even when no rule mentions it.

## Decisions

Each failing check produces a *concern* naming the argument (or `<context>`)
and the label of its data. Any `require` concern denies the call; otherwise any
`confirm` concern asks the user, who sees the reason and the provenance of each
offending argument; otherwise the call is allowed.

## Checking a policy

```console
$ moon run cmd/bactrian -- policy examples/banking.policy
```

parses the file, prints it back in canonical form (`parse ∘ render` is the
identity — tested, including reasons that contain `"`, `\` and control
characters, which are written with JSON escapes `\"` and `\\`), and rejects a
policy whose rules or audiences mention tools or arguments that do not exist
(an unknown argument would make a condition silently pass), reporting tools
without a policy as a warning.
