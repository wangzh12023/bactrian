///|
/// Performs a banking tool call against the simulated environment.
///
/// Besides the value, the result says who authored each part and who may read
/// it (adapted from CaMeL's annotations of AgentDojo):
///
/// - a transaction is readable by its two parties, and its subject was written
///   by its sender — an external party unless the sender is the user;
/// - file contents are untrusted (`read_file` is not a trusted tool) but not
///   secret;
/// - the balance and the user's profile are readable only by the user.
pub fn Bank::call(
  self : Bank,
  tool : String,
  args : Map[String, Json],
) -> @runtime.ToolResult raise {
  let str = fn(name : String) -> String raise {
    match args.get(name) {
      Some(String(s)) => s
      Some(Number(n, ..)) => n.to_string()
      _ => fail("argument `\{name}` must be a string")
    }
  }
  let opt_str = fn(name : String) -> String? {
    match args.get(name) {
      Some(String(s)) => Some(s)
      _ => None
    }
  }
  let num = fn(name : String) -> Double raise {
    match args.get(name) {
      Some(Number(n, ..)) => n
      Some(String(s)) =>
        @string.parse_double(s) catch {
          _ => fail("argument `\{name}` must be a number")
        }
      _ => fail("argument `\{name}` must be a number")
    }
  }
  let only_user = @label.Readers::only([])
  let message = fn(text : String) -> @runtime.ToolResult {
    @runtime.ToolResult::plain({ "message": Json::string(text) })
  }
  match tool {
    "get_iban" => @runtime.ToolResult::plain(Json::string(self.iban))
    "get_balance" =>
      @runtime.ToolResult::plain(Json::number(self.balance), readers=only_user)
    "get_most_recent_transactions" => {
      let n = match args.get("n") {
        Some(Number(n, ..)) => n.to_int()
        _ => 100
      }
      let start = (self.transactions.length() - n).max(0)
      transaction_result(self.transactions[start:].to_owned())
    }
    "get_scheduled_transactions" => transaction_result(self.scheduled)
    "read_file" => {
      let path = str("file_path")
      match self.files.get(path) {
        // A document the user received is no secret from whoever sent it,
        // and the simulated file system does not record who that was: file
        // contents are readable by anyone but, since `read_file` is not a
        // trusted tool, never trusted. (CaMeL labels them private instead,
        // which also blocks paying a bill to the account printed on it.)
        Some(text) => @runtime.ToolResult::plain(Json::string(text))
        None => fail("file not found: \{path}")
      }
    }
    "get_user_info" =>
      @runtime.ToolResult::plain(
        {
          "first_name": Json::string(self.first_name),
          "last_name": Json::string(self.last_name),
          "street": Json::string(self.street),
          "city": Json::string(self.city),
        },
        readers=only_user,
      )
    "send_money" => {
      let t = tx(
        self.next_id(),
        self.iban,
        str("recipient"),
        num("amount"),
        str("subject"),
        str("date"),
        false,
      )
      self.transactions.push(t)
      message("Transaction to \{t.recipient} for \{t.amount} sent.")
    }
    "schedule_transaction" => {
      let recurring = match args.get("recurring") {
        Some(True) => true
        _ => false
      }
      let t = tx(
        self.next_id(),
        self.iban,
        str("recipient"),
        num("amount"),
        str("subject"),
        str("date"),
        recurring,
      )
      self.scheduled.push(t)
      message("Transaction to \{t.recipient} for \{t.amount} scheduled.")
    }
    "update_scheduled_transaction" => {
      let id = num("id").to_int()
      match self.scheduled.search_by(t => t.id == id) {
        None => fail("Transaction with ID \{id} not found.")
        Some(i) => {
          let t = self.scheduled[i]
          self.scheduled[i] = {
            ..t,
            recipient: opt_str("recipient").unwrap_or(t.recipient),
            amount: match args.get("amount") {
              Some(Number(n, ..)) => n
              _ => t.amount
            },
            subject: opt_str("subject").unwrap_or(t.subject),
            date: opt_str("date").unwrap_or(t.date),
            recurring: match args.get("recurring") {
              Some(True) => true
              Some(False) => false
              _ => t.recurring
            },
          }
          message("Transaction with ID \{id} updated.")
        }
      }
    }
    "update_password" => {
      self.password = str("password")
      message("Password updated.")
    }
    "update_user_info" => {
      if opt_str("first_name") is Some(v) {
        self.first_name = v
      }
      if opt_str("last_name") is Some(v) {
        self.last_name = v
      }
      if opt_str("street") is Some(v) {
        self.street = v
      }
      if opt_str("city") is Some(v) {
        self.city = v
      }
      message("User information updated.")
    }
    _ => fail("unknown tool \{tool}")
  }
}

///|
/// A list of transactions, each readable by its two parties and with a
/// subject authored by its sender.
fn transaction_result(txs : Array[Transaction]) -> @runtime.ToolResult {
  let parties : Map[String, Array[@label.Source]] = Map([])
  let readers : Map[String, @label.Readers] = Map([])
  for i, t in txs {
    let who = [t.sender, t.recipient].filter(p => p != "me" && p != USER_IBAN)
    readers["[\{i}]"] = @label.Readers::only(who)
    if t.sender != "me" && t.sender != USER_IBAN {
      parties["[\{i}].subject"] = [Party(t.sender)]
    }
  }
  {
    value: Json::array(txs.map(t => t.to_json())),
    readers: Public,
    paths: { parties, readers, },
  }
}
