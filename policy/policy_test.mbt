///|
using @label {type Label, type Readers}

///|
using @policy {type Policy, type CallView, type ArgView}

///|
fn plan_arg(v : Json) -> ArgView {
  { value: v, label: Label::plan(), }
}

///|
fn file_arg(v : Json, readers? : Readers = Public) -> ArgView {
  let l = Label::tool("read_file", readers~)
  { value: v, label: l, }
}

///|
fn call(
  tool : String,
  args : Array[(String, ArgView)],
  context? : Label = Label::plan(),
) -> CallView {
  { tool, args: Map::from_array(args), context, }
}

///|
let banking : Policy = @policy.parse_policy(
  (
    #|policy "banking"
    #|self "me", "DE89370400440532013000"
    #|trust tools get_balance, get_iban
    #|context confirm
    #|
    #|read read_file, get_balance, get_iban, get_most_recent_transactions
    #|
    #|effect send_money audience recipient
    #|  require trusted(recipient) : "the payee must come from you, not from data"
    #|  confirm at_most(amount, 1000) : "transfers above 1000 need your approval"
    #|
    #|effect update_password
    #|  require trusted(password) : "a new password must come from you"
  ),
) catch {
  PolicySyntaxError(line~, message~) =>
    abort("bad test policy at line \{line}: \{message}")
}

///|
test "a transfer the user asked for is allowed" {
  let v = banking.check(
    call("send_money", [
      ("recipient", plan_arg("GB29NWBK60161331926819")),
      ("amount", plan_arg(98.7)),
      ("subject", plan_arg("Car rental")),
    ]),
  )
  debug_inspect(v.decision, content="Allow")
}

///|
test "a payee taken from a file is denied, with the culprit named" {
  let v = banking.check(
    call("send_money", [
      ("recipient", file_arg("UK12345678901234567890")),
      ("amount", file_arg(98.7)),
      ("subject", plan_arg("Car rental")),
    ]),
  )
  debug_inspect(
    v.decision,
    content=(
      #|Deny("the payee must come from you, not from data")
    ),
  )
  inspect(v.concerns.map(c => c.culprit).join(","), content="recipient")
  inspect(v.concerns[0].label.render(), content="tool:read_file|public")
}

///|
test "a large amount asks instead of denying" {
  let v = banking.check(
    call("send_money", [
      ("recipient", plan_arg("US122000000121212121212")),
      ("amount", plan_arg(2200)),
    ]),
  )
  debug_inspect(
    v.decision,
    content=(
      #|Ask("transfers above 1000 need your approval")
    ),
  )
}

///|
let mail : Policy = @policy.parse_policy(
  (
    #|policy "mail"
    #|self "emma@bluesparrow.com"
    #|effect send_email audience recipients
    #|  confirm trusted(recipients) : "the recipients were not chosen by you"
  ),
) catch {
  PolicySyntaxError(line~, message~) =>
    abort("bad test policy at line \{line}: \{message}")
}

///|
fn email_arg(v : Json, sender : String) -> ArgView {
  let l = Label::tool("get_received_emails").join({
    ..Label::bottom(),
    sources: Label::bottom().sources.add(Party(sender)),
  })
  { value: v, label: l, }
}

///|
test "private data never reaches an audience chosen by data that may not read it" {
  // The recipient comes from an e-mail (an attacker can choose it), and the
  // body carries data only the user may read: exfiltration, denied.
  let secret : ArgView = {
    value: "reset code 482913",
    label: Label::tool("search_emails", readers=Readers::only([])),
  }
  let v = mail.check(
    call("send_email", [
      ("recipients", email_arg(["mallory@evil.com"], "mallory@evil.com")),
      ("body", secret),
    ]),
  )
  inspect(v.decision is Deny(_), content="true")
  inspect(v.concerns.map(c => c.culprit).join(","), content="body,recipients")
  // A reply whose content its recipient may read only needs confirmation,
  // because the recipient still came from data.
  let thread : ArgView = {
    value: "Re: lunch?",
    label: Label::tool(
      "get_received_emails",
      readers=Readers::only(["bob@acme.com", "emma@bluesparrow.com"]),
    ),
  }
  let reply = mail.check(
    call("send_email", [
      ("recipients", email_arg(["bob@acme.com"], "bob@acme.com")),
      ("body", thread),
    ]),
  )
  debug_inspect(
    reply.decision,
    content=(
      #|Ask("the recipients were not chosen by you")
    ),
  )
  // When the user names the recipient, sending them private data is the
  // user's decision: allowed.
  let chosen = mail.check(
    call("send_email", [
      ("recipients", plan_arg(["bob@acme.com"])),
      ("body", secret),
    ]),
  )
  debug_inspect(chosen.decision, content="Allow")
}

///|
test "the user's own identities do not count as an audience" {
  let secret : ArgView = {
    value: "password123",
    label: Label::tool("get_user_info", readers=Readers::only([])),
  }
  let v = banking.check(
    call("send_money", [
      ("recipient", plan_arg("DE89370400440532013000")),
      ("amount", plan_arg(1)),
      ("subject", secret),
    ]),
  )
  debug_inspect(v.decision, content="Allow")
}

///|
test "an effect decided by untrusted data needs confirmation" {
  let v = banking.check(
    call(
      "update_password",
      [("password", plan_arg("hunter2"))],
      context=Label::tool("read_file"),
    ),
  )
  debug_inspect(
    v.decision,
    content=(
      #|Ask("this action only happens because of a decision made on untrusted data")
    ),
  )
  inspect(v.concerns[0].culprit, content="<context>")
}

///|
test "unknown tools fail closed and reads are free" {
  debug_inspect(
    banking.check(call("delete_account", [])).decision,
    content=(
      #|Deny("no policy covers this tool")
    ),
  )
  debug_inspect(
    banking.check(
      call(
        "read_file",
        [("file_path", file_arg("x"))],
        context=Label::tool("x"),
      ),
    ).decision,
    content="Allow",
  )
}

///|
test "an audience that is not a name fails closed" {
  let v = banking.check(
    call("send_money", [("recipient", file_arg(42)), ("amount", plan_arg(1))]),
  )
  debug_inspect(
    v.decision,
    content=(
      #|Deny("the audience of `send_money` must be a name or a list of names")
    ),
  )
}

///|
test "render and parse round-trip" {
  let text = banking.render()
  inspect(
    text,
    content=(
      #|policy "banking"
      #|self "me", "DE89370400440532013000"
      #|trust tools get_balance, get_iban
      #|context confirm
      #|
      #|read get_balance
      #|
      #|read get_iban
      #|
      #|read get_most_recent_transactions
      #|
      #|read read_file
      #|
      #|effect send_money audience recipient
      #|  require trusted(recipient) : "the payee must come from you, not from data"
      #|  confirm at_most(amount, 1000) : "transfers above 1000 need your approval"
      #|
      #|effect update_password
      #|  require trusted(password) : "a new password must come from you"
      #|
    ),
  )
  inspect(@policy.parse_policy(text).render() == text, content="true")
}

///|
test "combinators and literal conditions parse" {
  let p = @policy.parse_policy(
    (
      #|policy "mix"
      #|effect post audience channel
      #|  require all(trusted(channel), not(public(body))) : "a"
      #|  confirm any(one_of(channel, ["general", "random"]), present(force)) : "b"
      #|  require readable_by(body, ["bob", "carol"]) : "c"
    ),
  )
  inspect(
    p.render(),
    content=(
      #|policy "mix"
      #|
      #|effect post audience channel
      #|  require all(trusted(channel), not(public(body))) : "a"
      #|  confirm any(one_of(channel, ["general", "random"]), present(force)) : "b"
      #|  require readable_by(body, ["bob", "carol"]) : "c"
      #|
    ),
  )
}

///|
test "syntax errors carry line numbers" {
  let bad =
    #|policy "x"
    #|effect send
    #|  require trusted(to : "missing paren"
  try @policy.parse_policy(bad) catch {
    PolicySyntaxError(line~, message~) =>
      inspect("\{line}: \{message}", content="3: expected `)`")
  } noraise {
    _ => fail("expected a syntax error")
  }
  try @policy.parse_policy("  require trusted(x) : \"orphan\"") catch {
    PolicySyntaxError(line~, message~) =>
      inspect(
        "\{line}: \{message}",
        content="1: `require` must be indented under an `effect`",
      )
  } noraise {
    _ => fail("expected a syntax error")
  }
}

///|
test "validate finds rules about arguments that do not exist" {
  let sigs = Map::from_array([
    ("send_money", ["recipient", "amount", "subject", "date"]),
    ("update_password", ["new_password"]),
    ("read_file", ["file_path"]),
    ("schedule_transaction", ["recipient", "amount"]),
  ])
  let problems = banking.validate(sigs)
  problems.sort_by((a, b) => a.lexical_compare(b))
  inspect(
    problems.join("\n"),
    content=(
      #|`update_password`: rule `trusted(password)` refers to unknown argument `password`
      #|no policy for tool `schedule_transaction`: calls will be decided by the default
      #|policy for unknown tool `get_balance`
      #|policy for unknown tool `get_iban`
      #|policy for unknown tool `get_most_recent_transactions`
    ),
  )
  // A tool without a policy is denied by default: a gap, not an error.
  let errors = banking.errors(sigs)
  errors.sort_by((a, b) => a.lexical_compare(b))
  inspect(
    errors.join("\n"),
    content=(
      #|`update_password`: rule `trusted(password)` refers to unknown argument `password`
      #|policy for unknown tool `get_balance`
      #|policy for unknown tool `get_iban`
      #|policy for unknown tool `get_most_recent_transactions`
    ),
  )
}

///|
test "a misspelt argument name is an error, because the rule would never fire" {
  let typo = @policy.parse_policy(
    (
      #|policy "typo"
      #|effect send_money audience recipient
      #|  require trusted(recipeint) : "the payee must come from you"
    ),
  )
  let sigs = Map::from_array([
    ("send_money", ["recipient", "amount", "subject", "date"]),
  ])
  inspect(
    typo.errors(sigs).join("\n"),
    content="`send_money`: rule `trusted(recipeint)` refers to unknown argument `recipeint`",
  )
  inspect(
    typo.validate(sigs).join("\n"),
    content="`send_money`: rule `trusted(recipeint)` refers to unknown argument `recipeint`",
  )
  // This is why such a policy must be refused: the checker cannot tell the
  // misspelt argument from an optional one the plan left out, so the rule
  // holds even for a payee taken from a file.
  let v = typo.check(
    call("send_money", [
      ("recipient", file_arg("US133000000121212121212")),
      ("amount", plan_arg(1)),
    ]),
  )
  debug_inspect(v.decision, content="Allow")
  // Spelt correctly, the same rule denies that call.
  let fixed = @policy.parse_policy(
    (
      #|policy "fixed"
      #|effect send_money audience recipient
      #|  require trusted(recipient) : "the payee must come from you"
    ),
  )
  debug_inspect(
    fixed.check(
      call("send_money", [
        ("recipient", file_arg("US133000000121212121212")),
        ("amount", plan_arg(1)),
      ]),
    ).decision,
    content=(
      #|Deny("the payee must come from you")
    ),
  )
  let misspelt_audience = @policy.parse_policy(
    (
      #|policy "typo"
      #|effect send_money audience recipients
    ),
  )
  inspect(
    misspelt_audience.errors(sigs).join("\n"),
    content="`send_money`: audience refers to unknown argument `recipients`",
  )
}

///|
test "conditions on an omitted optional argument" {
  // `update_scheduled_transaction(id, recipient=None, ...)`: when the plan
  // leaves `recipient` out, there is no data whose source could be wrong, so
  // `trusted` and `public` hold; a condition on its value does not.
  let p = @policy.parse_policy(
    (
      #|policy "optional"
      #|effect update_scheduled_transaction
      #|  require trusted(recipient) : "the payee must come from you"
      #|  confirm at_most(amount, 1000) : "large amounts need your approval"
    ),
  )
  let only_id = call("update_scheduled_transaction", [("id", plan_arg(7))])
  let v = p.check(only_id)
  debug_inspect(
    v.decision,
    content=(
      #|Ask("large amounts need your approval")
    ),
  )
  inspect(v.concerns.map(c => c.culprit).join(","), content="amount")
}

///|
test "quoted strings use JSON escapes and render back the same" {
  let text =
    #|policy "say \"hi\""
    #|self "C:\\Users\\me"
    #|effect post audience to
    #|  require readable_by(body, ["a\"b"]) : "a \"quoted\" reason with a \\ and a\nnewline"
  let p = @policy.parse_policy(text)
  inspect(p.name, content="say \"hi\"")
  inspect(p.self_ids[0], content="C:\\Users\\me")
  let reason = p.tools["post"].rules[0].reason
  inspect(
    reason,
    content=(
      #|a "quoted" reason with a \ and a
      #|newline
    ),
  )
  let rendered = p.render()
  inspect(
    rendered,
    content=(
      #|policy "say \"hi\""
      #|self "C:\\Users\\me"
      #|
      #|effect post audience to
      #|  require readable_by(body, ["a\"b"]) : "a \"quoted\" reason with a \\ and a\nnewline"
      #|
    ),
  )
  assert_eq(@policy.parse_policy(rendered).render(), rendered)
  inspect(
    @policy.parse_policy("policy \"\\u00e9\\ud83d\\ude00\"").name,
    content="é😀",
  )
  // `\t` is a tab, as in JSON; an escape JSON does not have is an error.
  inspect(@policy.parse_policy("policy \"C:\\temp\"").name, content="C:\temp")
  try @policy.parse_policy("policy \"C:\\quarterly\"") catch {
    PolicySyntaxError(line~, message~) =>
      inspect(
        "\{line}: \{message}",
        content="1: unknown escape `\\q` in a string (write `\\\\` for a backslash)",
      )
  } noraise {
    _ => fail("expected a syntax error")
  }
  try @policy.parse_policy("policy \"\\ud83d alone\"") catch {
    PolicySyntaxError(line~, message~) =>
      inspect(
        "\{line}: \{message}",
        content="1: `\\u` must be followed by four hex digits of a character",
      )
  } noraise {
    _ => fail("expected a syntax error")
  }
  try @policy.parse_policy("policy \"unterminated\\\"") catch {
    PolicySyntaxError(line~, message~) =>
      inspect("\{line}: \{message}", content="1: unterminated string")
  } noraise {
    _ => fail("expected a syntax error")
  }
}
