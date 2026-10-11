///|
/// A problem in a policy file, with its 1-based line number.
pub(all) suberror PolicySyntaxError {
  PolicySyntaxError(line~ : Int, message~ : String)
} derive(Debug)

///|
priv enum Tok {
  Ident(String)
  Str(String)
  Num(Double)
  Punct(Char)
}

///|
fn tokenize(
  line : StringView,
  lineno : Int,
) -> Array[Tok] raise PolicySyntaxError {
  let toks = []
  let chars = line.to_owned().to_array()
  let n = chars.length()
  let mut i = 0
  while i < n {
    let c = chars[i]
    if c == '#' {
      break
    }
    if c is (' ' | '\t' | '\r') {
      i += 1
      continue
    }
    if c is ('(' | ')' | '[' | ']' | ',' | ':') {
      toks.push(Punct(c))
      i += 1
      continue
    }
    if c == '"' {
      let sb = StringBuilder()
      i += 1
      while i < n && chars[i] != '"' {
        if chars[i] == '\\' && i + 1 < n {
          i += 1
        }
        sb.write_char(chars[i])
        i += 1
      }
      if i >= n {
        raise PolicySyntaxError(line=lineno, message="unterminated string")
      }
      i += 1
      toks.push(Str(sb.to_string()))
      continue
    }
    if c.is_ascii_digit() ||
      (c == '-' && i + 1 < n && chars[i + 1].is_ascii_digit()) {
      let start = i
      i += 1
      while i < n && (chars[i].is_ascii_digit() || chars[i] == '.') {
        i += 1
      }
      let text = String::from_array(chars[start:i])
      let v = @string.parse_double(text) catch {
        _ =>
          raise PolicySyntaxError(line=lineno, message="bad number `\{text}`")
      }
      toks.push(Num(v))
      continue
    }
    if c.is_ascii_alphabetic() || c == '_' {
      let start = i
      while i < n &&
            (
              chars[i].is_ascii_alphabetic() ||
              chars[i].is_ascii_digit() ||
              chars[i] is ('_' | '.' | '-')
            ) {
        i += 1
      }
      toks.push(Ident(String::from_array(chars[start:i])))
      continue
    }
    raise PolicySyntaxError(line=lineno, message="unexpected character `\{c}`")
  }
  toks
}

///|
priv struct Cursor {
  toks : Array[Tok]
  mut pos : Int
  line : Int
}

///|
fn Cursor::peek(self : Cursor) -> Tok? {
  self.toks.get(self.pos)
}

///|
fn Cursor::next(self : Cursor) -> Tok raise PolicySyntaxError {
  match self.toks.get(self.pos) {
    Some(t) => {
      self.pos += 1
      t
    }
    None =>
      raise PolicySyntaxError(line=self.line, message="unexpected end of line")
  }
}

///|
fn Cursor::fail(self : Cursor, message : String) -> PolicySyntaxError {
  PolicySyntaxError(line=self.line, message~)
}

///|
fn Cursor::expect(self : Cursor, c : Char) -> Unit raise PolicySyntaxError {
  match self.next() {
    Punct(p) if p == c => ()
    _ => raise self.fail("expected `\{c}`")
  }
}

///|
fn Cursor::ident(self : Cursor) -> String raise PolicySyntaxError {
  match self.next() {
    Ident(s) => s
    _ => raise self.fail("expected a name")
  }
}

///|
fn Cursor::at_end(self : Cursor) -> Bool {
  self.pos >= self.toks.length()
}

///|
/// Comma-separated names or strings, until the end of the line.
fn Cursor::name_list(self : Cursor) -> Array[String] raise PolicySyntaxError {
  let out = []
  while !self.at_end() {
    match self.next() {
      Ident(s) | Str(s) => out.push(s)
      _ => raise self.fail("expected a name")
    }
    if !self.at_end() {
      self.expect(',')
    }
  }
  out
}

///|
fn Cursor::literal(self : Cursor) -> Json raise PolicySyntaxError {
  match self.next() {
    Str(s) => Json::string(s)
    Num(n) => Json::number(n)
    Ident("true") => Json::boolean(true)
    Ident("false") => Json::boolean(false)
    Ident("null") => Json::null()
    _ => raise self.fail("expected a literal")
  }
}

///|
fn Cursor::cond(self : Cursor) -> Cond raise PolicySyntaxError {
  let head = self.ident()
  if head == "context_trusted" {
    return ContextTrusted
  }
  self.expect('(')
  let result : Cond = match head {
    "trusted" => Trusted(self.ident())
    "public" => Public(self.ident())
    "present" => Present(self.ident())
    "readable_by" => {
      let arg = self.ident()
      self.expect(',')
      self.expect('[')
      let ps = []
      while self.peek() is Some(Str(p)) {
        self.pos += 1
        ps.push(p)
        if self.peek() is Some(Punct(',')) {
          self.pos += 1
        }
      }
      self.expect(']')
      ReadableBy(arg, ps)
    }
    "at_most" => {
      let arg = self.ident()
      self.expect(',')
      match self.next() {
        Num(n) => AtMost(arg, n)
        _ => raise self.fail("at_most expects a number")
      }
    }
    "one_of" => {
      let arg = self.ident()
      self.expect(',')
      self.expect('[')
      let xs = []
      while !(self.peek() is Some(Punct(']'))) {
        xs.push(self.literal())
        if self.peek() is Some(Punct(',')) {
          self.pos += 1
        }
      }
      self.expect(']')
      OneOf(arg, xs)
    }
    "all" | "any" => {
      let cs = [self.cond()]
      while self.peek() is Some(Punct(',')) {
        self.pos += 1
        cs.push(self.cond())
      }
      if head == "all" {
        All(cs)
      } else {
        Any(cs)
      }
    }
    "not" => Not(self.cond())
    other => raise self.fail("unknown condition `\{other}`")
  }
  self.expect(')')
  result
}

///|
/// Parses a policy file.
///
/// ```text
/// policy "banking"
/// self "me", "DE89370400440532013000"
/// trust tools get_balance, get_iban
/// trust parties "bank@bank.com"
/// context confirm            # or: context require
///
/// read get_most_recent_transactions
/// effect send_money audience recipient
///   require trusted(recipient) : "the payee must come from you"
///   confirm at_most(amount, 1000) : "large transfers need your approval"
/// ```
///
/// Rules are indented under their `effect`. `require` blocks the call when the
/// condition fails; `confirm` asks the user. Lines starting with `#` are
/// comments.
pub fn parse_policy(text : String) -> Policy raise PolicySyntaxError {
  let mut name = "policy"
  let self_ids = []
  let trusted_tools = []
  let trusted_parties = []
  let mut context_integrity : Severity? = None
  let mut unknown_tool : Decision = Deny("no policy covers this tool")
  let tools : Array[ToolPolicy] = []
  for i, raw in text.split("\n").collect() {
    let lineno = i + 1
    let toks = tokenize(raw, lineno)
    if toks.is_empty() {
      continue
    }
    let cur = { toks, pos: 0, line: lineno, }
    let indented = raw.has_prefix(" ") || raw.has_prefix("\t")
    match cur.ident() {
      "policy" =>
        match cur.next() {
          Str(s) | Ident(s) => name = s
          _ => raise cur.fail("expected a policy name")
        }
      "self" => self_ids.append(cur.name_list())
      "trust" =>
        match cur.ident() {
          "tools" => trusted_tools.append(cur.name_list())
          "parties" => trusted_parties.append(cur.name_list())
          other =>
            raise cur.fail(
              "expected `tools` or `parties` after `trust`, got `\{other}`",
            )
        }
      "context" =>
        context_integrity = match cur.ident() {
          "require" => Some(Block)
          "confirm" => Some(Confirm)
          "ignore" => None
          other => raise cur.fail("unknown context mode `\{other}`")
        }
      "unknown" =>
        unknown_tool = match cur.ident() {
          "allow" => Allow
          "confirm" => Ask("no policy covers this tool")
          "deny" => Deny("no policy covers this tool")
          other => raise cur.fail("unknown default `\{other}`")
        }
      "read" =>
        for t in cur.name_list() {
          tools.push(read(t))
        }
      "effect" => {
        let tool = cur.ident()
        let audience = if !cur.at_end() {
          guard cur.ident() is "audience" else {
            raise cur.fail("expected `audience`")
          }
          cur.name_list()
        } else {
          []
        }
        tools.push(effect(tool, audience~, []))
      }
      "require" | "confirm" as verb => {
        guard indented && tools.last() is Some(tp) && tp.kind is Effect else {
          raise cur.fail("`\{verb}` must be indented under an `effect`")
        }
        let cond = cur.cond()
        cur.expect(':')
        let reason = match cur.next() {
          Str(s) => s
          _ => raise cur.fail("expected a quoted reason")
        }
        tp.rules.push({
          cond,
          otherwise: if verb == "require" {
            Block
          } else {
            Confirm
          },
          reason,
        })
      }
      other => raise cur.fail("unknown directive `\{other}`")
    }
    if !cur.at_end() {
      raise cur.fail("unexpected text at end of line")
    }
  }
  Policy::new(
    name,
    tools,
    trusted_tools~,
    trusted_parties~,
    self_ids~,
    context_integrity?,
    unknown_tool~,
  )
}
