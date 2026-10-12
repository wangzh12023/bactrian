///|
let str_methods : Array[String] = [
  "lower", "upper", "strip", "lstrip", "rstrip", "split", "rsplit", "join", "replace",
  "startswith", "endswith", "find", "rfind", "index", "count", "isdigit", "isalpha",
  "isalnum", "isspace", "islower", "isupper", "title", "capitalize", "splitlines",
  "partition", "removeprefix", "removesuffix", "format", "zfill",
]

///|
let list_methods : Array[String] = [
  "append", "extend", "insert", "pop", "remove", "clear", "index", "count", "sort",
  "reverse", "copy",
]

///|
let dict_methods : Array[String] = [
  "get", "keys", "values", "items", "pop", "update", "setdefault", "copy", "clear",
]

///|
fn method_exists(v : Value, name : String) -> Bool {
  match v {
    VStr(_) => str_methods.contains(name)
    VList(_) => list_methods.contains(name)
    VDict(_) => dict_methods.contains(name)
    VTuple(_) => name is ("index" | "count")
    VRecord(_) => name is ("model_dump" | "dict")
    _ => false
  }
}

///|
fn Ctx::call_method(
  self : Ctx,
  recv : Item,
  name : String,
  a : Args,
  span : @basic.Span,
) -> Item raise PlanError {
  // Mutating a container in place is only sound when we can see *which*
  // container is mutated. If the receiver reference was chosen by untrusted
  // data (`y = a if <data> else b; y.clear()`), a purely dynamic tracker
  // cannot taint the sibling container the other world would have mutated. We
  // fail closed: an in-place mutation is refused when the receiver reference
  // is not trusted. Plan-built containers (`acc = []`) keep a trusted
  // reference and stay mutable; to reorder tool data, use `sorted(xs)`.
  if is_mutating_method(recv.value, name) &&
    !self.world.policy.is_trusted(recv.label) {
    raise unsupported(
      "`\{name}` would modify a value selected by untrusted data; build a new value (e.g. with `sorted`, a comprehension or `+`) instead",
      span,
    )
  }
  match recv.value {
    VStr(s) => self.str_method(recv, s, name, a, span)
    VList(l) => self.list_method(recv, l, name, a, span)
    VDict(d) => self.dict_method(recv, d, name, a, span)
    VTuple(xs) =>
      self.list_method(recv, { items: xs, shape: recv.label, }, name, a, span)
    VRecord(r) => {
      // `model_dump()` turns a record into a dict.
      let entries : Map[String, (Item, Item)] = Map([])
      for k, v in r.fields {
        entries["s:" + k] = (str_item(k, recv.label), v)
      }
      { value: VDict({ entries, shape: recv.label, }), label: recv.label, }
    }
    other =>
      raise type_error(
        "'\{other.type_name()}' object has no method '\{name}'",
        span,
      )
  }
}

///|
fn arg_str(
  a : Args,
  i : Int,
  name : String,
  span : @basic.Span,
) -> (String, Label) raise PlanError {
  match a.pos.get(i) {
    Some({ value: VStr(s), label, }) => (s, label)
    Some(other) =>
      raise type_error(
        "\{name}() argument must be str, not '\{other.value.type_name()}'",
        span,
      )
    None => raise type_error("\{name}() missing an argument", span)
  }
}

///|
fn Ctx::str_method(
  self : Ctx,
  recv : Item,
  s : String,
  name : String,
  a : Args,
  span : @basic.Span,
) -> Item raise PlanError {
  let args_label = a.pos.fold(init=Label::bottom(), (acc, x) => {
    acc.join(x.deep())
  })
  let l = recv.label.join(args_label)
  let text = fn(t : String) -> Item { str_item(t, l) }
  let boolean = fn(b : Bool) -> Item { { value: VBool(b), label: l, } }
  let strs = fn(parts : Array[String]) -> Item {
    list_item(parts.map(p => str_item(p, l)), l)
  }
  match name {
    "lower" => text(s.to_lower())
    "upper" => text(s.to_upper())
    "strip" | "lstrip" | "rstrip" => {
      let chars = match a.pos.get(0) {
        Some({ value: VStr(c), .. }) => c
        _ => " \t\n\r"
      }
      text(
        match name {
          "strip" => s.trim(chars~).to_owned()
          "lstrip" => s.trim_start(chars~).to_owned()
          _ => s.trim_end(chars~).to_owned()
        },
      )
    }
    "split" | "rsplit" =>
      match a.pos.get(0) {
        Some({ value: VStr(sep), .. }) if sep != "" =>
          strs(s.split(sep).map(p => p.to_owned()).collect())
        _ =>
          strs(
            s
            .split(" ")
            .map(p => p.trim().to_owned())
            .filter(p => p != "")
            .collect(),
          )
      }
    "splitlines" =>
      strs(s.split("\n").map(p => p.trim_end(chars="\r").to_owned()).collect())
    "join" => {
      let parts = match a.pos.get(0) {
        Some(x) => self.iterate(x, span)
        None => raise type_error("join() takes exactly one argument", span)
      }
      let pieces = []
      for p in parts {
        match p.value {
          VStr(t) => pieces.push(t)
          other =>
            raise type_error(
              "sequence item: expected str instance, \{other.type_name()} found",
              span,
            )
        }
      }
      text(pieces.join(s))
    }
    "replace" => {
      let (old, _) = arg_str(a, 0, name, span)
      let (new, _) = arg_str(a, 1, name, span)
      text(if old == "" { s } else { s.replace_all(old~, new~) })
    }
    "startswith" => boolean(s.has_prefix(arg_str(a, 0, name, span).0))
    "endswith" => boolean(s.has_suffix(arg_str(a, 0, name, span).0))
    "find" | "index" => {
      let (needle, _) = arg_str(a, 0, name, span)
      match s.find(needle) {
        Some(i) => { value: VInt(i.to_int64()), label: l, }
        None =>
          if name == "find" {
            { value: VInt(-1L), label: l, }
          } else {
            raise err(
              Runtime("ValueError"),
              "substring not found",
              span,
              label=l,
            )
          }
      }
    }
    "rfind" => {
      let (needle, _) = arg_str(a, 0, name, span)
      {
        value: VInt(s.rev_find(needle).map(i => i.to_int64()).unwrap_or(-1L)),
        label: l,
      }
    }
    "count" => {
      let (needle, _) = arg_str(a, 0, name, span)
      let n = if needle == "" {
        s.char_length() + 1
      } else {
        s.split(needle).count() - 1
      }
      { value: VInt(n.to_int64()), label: l, }
    }
    "isdigit" => boolean(s != "" && s.iter().all(c => c.is_ascii_digit()))
    "isalpha" =>
      boolean(
        s != "" &&
        s.iter().all(c => c.is_ascii_alphabetic() || c.to_int() > 127),
      )
    "isalnum" =>
      boolean(
        s != "" &&
        s
        .iter()
        .all(c => {
          c.is_ascii_alphabetic() || c.is_ascii_digit() || c.to_int() > 127
        }),
      )
    "isspace" => boolean(s != "" && s.iter().all(c => c.is_whitespace()))
    "islower" => boolean(s.to_lower() == s && s.to_upper() != s)
    "isupper" => boolean(s.to_upper() == s && s.to_lower() != s)
    "title" | "capitalize" => {
      let sb = StringBuilder()
      let mut start = true
      for c in s {
        if start {
          sb.write_string(c.to_string().to_upper())
        } else if name == "title" {
          sb.write_string(c.to_string())
        } else {
          sb.write_string(c.to_string().to_lower())
        }
        start = name == "title" &&
          !(c.is_ascii_alphabetic() || c.is_ascii_digit())
      }
      text(sb.to_string())
    }
    "partition" => {
      let (sep, _) = arg_str(a, 0, name, span)
      let parts = match s.split_once(sep) {
        Some((x, y)) => [x.to_owned(), sep, y.to_owned()]
        None => [s, "", ""]
      }
      { value: VTuple(parts.map(p => str_item(p, l))), label: l, }
    }
    "removeprefix" => {
      let (p, _) = arg_str(a, 0, name, span)
      text(s.strip_prefix(p).map(v => v.to_owned()).unwrap_or(s))
    }
    "removesuffix" => {
      let (p, _) = arg_str(a, 0, name, span)
      text(s.strip_suffix(p).map(v => v.to_owned()).unwrap_or(s))
    }
    "zfill" =>
      match a.pos.get(0) {
        Some({ value: VInt(w), .. }) => text(s.pad_start(w.to_int(), '0'))
        _ => raise type_error("zfill() needs an int", span)
      }
    "format" => {
      // Positional `{}` and `{0}` placeholders only.
      let sb = StringBuilder()
      let chars = s.to_array()
      let mut next = 0
      let mut i = 0
      let mut lbl = l
      while i < chars.length() {
        if chars[i] == '{' && i + 1 < chars.length() && chars[i + 1] == '{' {
          sb.write_char('{')
          i += 2
        } else if chars[i] == '}' &&
          i + 1 < chars.length() &&
          chars[i + 1] == '}' {
          sb.write_char('}')
          i += 2
        } else if chars[i] == '{' {
          let close = for j = i + 1; j < chars.length(); j = j + 1 {
            if chars[j] == '}' {
              break j
            }
          } nobreak {
            raise err(
              Runtime("ValueError"),
              "unmatched '{' in format string",
              span,
            )
          }
          let field = String::from_array(chars[i + 1:close])
          let idx = if field == "" {
            next += 1
            next - 1
          } else {
            @string.parse_int(field) catch {
              _ =>
                raise unsupported(
                  "only positional `{}` placeholders are available in format()",
                  span,
                )
            }
          }
          match a.pos.get(idx) {
            Some(v) => {
              sb.write_string(v.value.to_str())
              lbl = lbl.join(v.deep())
            }
            None =>
              raise err(
                Runtime("IndexError"),
                "format index \{idx} out of range",
                span,
              )
          }
          i = close + 1
        } else {
          sb.write_char(chars[i])
          i += 1
        }
      }
      str_item(sb.to_string(), lbl)
    }
    _ => raise type_error("'str' object has no method '\{name}'", span)
  }
}

///|
fn Ctx::list_method(
  self : Ctx,
  recv : Item,
  l : ListObj,
  name : String,
  a : Args,
  span : @basic.Span,
) -> Item raise PlanError {
  let plan = Label::plan()
  // Any change made here happens because execution reached this call.
  // Any change made here reveals that execution reached this call.
  let here = recv.label.join(self.flow())
  match name {
    "append" => {
      match a.pos {
        [x] => l.items.push(x.taint(here))
        _ => raise type_error("append() takes exactly one argument", span)
      }
      l.shape = l.shape.join(here)
      if l.items.length() > self.world.limits.max_list {
        raise err(
          Budget,
          "a list grew beyond \{self.world.limits.max_list} elements",
          span,
        )
      }
      none_item(plan)
    }
    "extend" => {
      let src = match a.pos {
        [x] => x
        _ => raise type_error("extend() takes exactly one argument", span)
      }
      for el in self.iterate(src, span) {
        l.items.push(el.taint(here))
      }
      l.shape = l.shape.join(here).join(src.top())
      none_item(plan)
    }
    "insert" =>
      match a.pos {
        [{ value: VInt(i), label: il, }, x] => {
          let n = l.items.length()
          let j = if i < 0L {
            (i.to_int() + n).max(0)
          } else {
            i.to_int().min(n)
          }
          l.items.insert(j, x.taint(here.join(il)))
          l.shape = l.shape.join(here).join(il)
          none_item(plan)
        }
        _ => raise type_error("insert() takes an index and a value", span)
      }
    "pop" => {
      if l.items.is_empty() {
        raise err(
          Runtime("IndexError"),
          "pop from empty list",
          span,
          label=recv.top(),
        )
      }
      let (i, il) = match a.pos {
        [] => (l.items.length() - 1, Label::bottom())
        [k] => (self.index_of(k, l.items.length(), span), k.label)
        _ => raise type_error("pop() takes at most 1 argument", span)
      }
      let v = l.items.remove(i)
      l.shape = l.shape.join(here).join(il)
      v.taint(here.join(il).join(l.shape))
    }
    "remove" => {
      let x = match a.pos {
        [x] => x
        _ => raise type_error("remove() takes exactly one argument", span)
      }
      let mut used = here.join(x.deep()).join(l.shape)
      let idx = for i, el in l.items {
        used = used.join(el.deep())
        if values_equal(el.value, x.value) {
          break Some(i)
        }
      } nobreak {
        None
      }
      l.shape = l.shape.join(used)
      match idx {
        Some(i) => {
          ignore(l.items.remove(i))
          none_item(plan)
        }
        None =>
          raise err(
            Runtime("ValueError"),
            "list.remove(x): x not in list",
            span,
            label=used,
          )
      }
    }
    "clear" => {
      l.items.clear()
      l.shape = l.shape.join(here)
      none_item(plan)
    }
    "index" | "count" => {
      let x = match a.pos {
        [x] => x
        _ => raise type_error("\{name}() takes exactly one argument", span)
      }
      let mut used = recv.top().join(x.deep())
      let mut count = 0
      let mut first : Int? = None
      for i, el in l.items {
        used = used.join(el.deep())
        if values_equal(el.value, x.value) {
          count += 1
          if first is None {
            first = Some(i)
          }
        }
      }
      if name == "count" {
        { value: VInt(count.to_int64()), label: used, }
      } else {
        match first {
          Some(i) => { value: VInt(i.to_int64()), label: used, }
          None =>
            raise err(
              Runtime("ValueError"),
              "value is not in list",
              span,
              label=used,
            )
        }
      }
    }
    "sort" => {
      let sorted = self.call_builtin("sorted", { pos: [recv], kw: a.kw, }, span)
      match sorted.value {
        VList(s) => {
          l.items.clear()
          l.items.append(s.items)
          l.shape = l.shape.join(s.shape).join(here)
        }
        _ => ()
      }
      none_item(plan)
    }
    "reverse" => {
      let rev = l.items.rev()
      l.items.clear()
      l.items.append(rev)
      l.shape = l.shape.join(here)
      none_item(plan)
    }
    "copy" => list_item(l.items.copy(), recv.label, shape=l.shape)
    _ => raise type_error("'list' object has no method '\{name}'", span)
  }
}

///|
fn Ctx::dict_method(
  self : Ctx,
  recv : Item,
  d : DictObj,
  name : String,
  a : Args,
  span : @basic.Span,
) -> Item raise PlanError {
  let plan = Label::plan()
  // Any change made here reveals that execution reached this call.
  let here = recv.label.join(self.flow())
  let key_arg = fn() -> (Item, String) raise PlanError {
    match a.pos.get(0) {
      Some(k) =>
        match key_of(k.value) {
          Some(kk) => (k, kk)
          None =>
            raise type_error("unhashable type: '\{k.value.type_name()}'", span)
        }
      None => raise type_error("\{name}() needs a key", span)
    }
  }
  match name {
    "get" => {
      let (k, kk) = key_arg()
      let found = d.entries.get(kk)
      // Whether the key exists is part of the shape.
      let via = here.join(k.label).join(d.shape)
      match found {
        Some((_, v)) => v.taint(via)
        None =>
          match a.pos.get(1) {
            Some(default) => default.taint(via)
            None => none_item(via)
          }
      }
    }
    "keys" =>
      list_item(
        d.entries.values().map(kv => kv.0.taint(here)).collect(),
        here,
        shape=here.join(d.shape),
      )
    "values" =>
      list_item(
        d.entries.values().map(kv => kv.1.taint(here)).collect(),
        here,
        shape=here.join(d.shape),
      )
    "items" =>
      list_item(
        d.entries
        .values()
        .map(kv => { value: VTuple([kv.0, kv.1]), label: here, })
        .collect(),
        here,
        shape=here.join(d.shape),
      )
    "pop" => {
      let (k, kk) = key_arg()
      let via = here.join(k.label).join(d.shape)
      d.shape = d.shape.join(here).join(k.label)
      match d.entries.get(kk) {
        Some((_, v)) => {
          d.entries.remove(kk)
          v.taint(via)
        }
        None =>
          match a.pos.get(1) {
            Some(default) => default.taint(via)
            None =>
              raise err(Runtime("KeyError"), k.value.repr(), span, label=via)
          }
      }
    }
    "setdefault" => {
      let (k, kk) = key_arg()
      // Whether the key is added depends on the key, whichever branch runs.
      d.shape = d.shape.join(here).join(k.label)
      let via = here.join(k.label).join(d.shape)
      match d.entries.get(kk) {
        Some((_, v)) => v.taint(via)
        None => {
          let v = a.pos.get(1).unwrap_or(none_item(plan)).taint(here)
          d.entries[kk] = (k, v)
          v.taint(via)
        }
      }
    }
    "update" => {
      match a.pos.get(0) {
        Some({ value: VDict(src), label, }) => {
          for kk, kv in src.entries {
            d.entries[kk] = (kv.0.taint(label), kv.1.taint(label.join(here)))
          }
          d.shape = d.shape.join(here).join(label).join(src.shape)
        }
        Some(_) => raise type_error("update() needs a dict", span)
        None => ()
      }
      for p in a.kw {
        d.entries["s:" + p.0] = (str_item(p.0, plan), p.1.taint(here))
        d.shape = d.shape.join(here)
      }
      none_item(plan)
    }
    "copy" => {
      let entries = d.entries.copy()
      { value: VDict({ entries, shape: d.shape, }), label: recv.label, }
    }
    "clear" => {
      d.entries.clear()
      d.shape = d.shape.join(here)
      none_item(plan)
    }
    _ => raise type_error("'dict' object has no method '\{name}'", span)
  }
}
