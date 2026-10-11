///|
fn Ctx::call_builtin(
  self : Ctx,
  name : String,
  a : Args,
  span : @basic.Span,
) -> Item raise PlanError {
  let plan = Label::plan()
  let arity = fn(n : Int) raise PlanError {
    if a.pos.length() != n {
      raise type_error(
        "\{name}() takes exactly \{n} argument(s) (\{a.pos.length()} given)",
        span,
      )
    }
  }
  match name {
    "print" => {
      let text = a.pos.map(x => x.value.to_str()).join(" ")
      let l = a.pos.fold(init=Label::plan().join(self.pc), (acc, x) => {
        acc.join(x.deep())
      })
      self.session.output.push((text, l))
      self.session.events.push(Print(text~, label=l))
      none_item(plan)
    }
    "len" => {
      arity(1)
      let x = a.pos[0]
      let n = match x.value {
        VStr(s) => s.char_length()
        VList(l) => l.items.length()
        VTuple(xs) => xs.length()
        VDict(d) => d.entries.length()
        other =>
          raise type_error(
            "object of type '\{other.type_name()}' has no len()",
            span,
          )
      }
      { value: VInt(n.to_int64()), label: x.top(), }
    }
    "str" =>
      match a.pos {
        [] => str_item("", plan)
        [x] => str_item(x.value.to_str(), x.deep())
        _ => raise type_error("str() takes at most 1 argument", span)
      }
    "repr" => {
      arity(1)
      str_item(a.pos[0].value.repr(), a.pos[0].deep())
    }
    "int" | "float" | "bool" =>
      match a.pos {
        [] =>
          match name {
            "int" => { value: VInt(0L), label: plan, }
            "float" => { value: VFloat(0.0), label: plan, }
            _ => { value: VBool(false), label: plan, }
          }
        [x] => {
          let l = x.deep()
          match (name, x.value) {
            ("bool", v) => { value: VBool(v.truthy()), label: l, }
            ("int", VStr(s)) => {
              let i = @string.parse_int(s.trim().to_owned()) catch {
                _ =>
                  raise err(
                    Runtime("ValueError"),
                    "invalid literal for int(): \{@basic.py_repr(s)}",
                    span,
                    label=l,
                  )
              }
              { value: VInt(i.to_int64()), label: l, }
            }
            ("float", VStr(s)) => {
              let f = @string.parse_double(s.trim().to_owned()) catch {
                _ =>
                  raise err(
                    Runtime("ValueError"),
                    "could not convert string to float: \{@basic.py_repr(s)}",
                    span,
                    label=l,
                  )
              }
              { value: VFloat(f), label: l, }
            }
            (_, v) =>
              match as_number(v) {
                Some(n) =>
                  if name == "int" {
                    { value: VInt(n.to_int64()), label: l, }
                  } else {
                    { value: VFloat(n), label: l, }
                  }
                None =>
                  raise type_error(
                    "\{name}() argument must be a string or a number, not '\{v.type_name()}'",
                    span,
                  )
              }
          }
        }
        _ => raise type_error("\{name}() takes at most 1 argument", span)
      }
    "list" | "tuple" | "set" =>
      match a.pos {
        [] =>
          if name == "tuple" {
            { value: VTuple([]), label: plan, }
          } else {
            list_item([], plan)
          }
        [x] => {
          let items = self.iterate(x, span)
          let items = if name == "set" { dedupe(items) } else { items }
          if name == "tuple" {
            { value: VTuple(items), label: x.top(), }
          } else {
            list_item(items, x.label, shape=x.top())
          }
        }
        _ => raise type_error("\{name}() takes at most 1 argument", span)
      }
    "dict" => {
      let entries : Map[String, (Item, Item)] = Map([])
      let mut shape = plan
      if a.pos.get(0) is Some(src) {
        shape = shape.join(src.top())
        match src.value {
          VDict(d) =>
            for k, kv in d.entries {
              entries[k] = kv
            }
          _ =>
            for pair in self.iterate(src, span) {
              match pair.value {
                VTuple([k, v]) | VList({ items: [k, v], .. }) =>
                  match key_of(k.value) {
                    Some(kk) => {
                      entries[kk] = (k.taint(pair.label), v.taint(pair.label))
                      shape = shape.join(k.label)
                    }
                    None =>
                      raise type_error(
                        "unhashable type: '\{k.value.type_name()}'",
                        span,
                      )
                  }
                _ => raise type_error("dict() needs pairs", span)
              }
            }
        }
      }
      for p in a.kw {
        entries["s:" + p.0] = (str_item(p.0, plan), p.1)
      }
      { value: VDict({ entries, shape, }), label: plan, }
    }
    "range" => {
      let nums = a.pos.map(x => {
        match x.value {
          VInt(i) => i
          VBool(b) => if b { 1L } else { 0L }
          other =>
            raise type_error(
              "'\{other.type_name()}' object cannot be interpreted as an integer",
              span,
            )
        }
      })
      let (start, stop, step) = match nums {
        [stop] => (0L, stop, 1L)
        [start, stop] => (start, stop, 1L)
        [start, stop, step] => (start, stop, step)
        _ => raise type_error("range expected 1 to 3 arguments", span)
      }
      if step == 0L {
        raise err(Runtime("ValueError"), "range() arg 3 must not be zero", span)
      }
      let l = a.pos.fold(init=plan, (acc, x) => acc.join(x.label))
      let items = []
      let mut i = start
      while (step > 0L && i < stop) || (step < 0L && i > stop) {
        items.push({ value: VInt(i), label: l, })
        if items.length() > self.world.limits.max_list {
          raise err(Budget, "range() is too large", span)
        }
        i += step
      }
      list_item(items, l)
    }
    "enumerate" => {
      let x = match a.pos {
        [x] => x
        [x, _] => x
        _ => raise type_error("enumerate() takes 1 or 2 arguments", span)
      }
      let start = match a.pos.get(1) {
        Some({ value: VInt(s), .. }) => s
        _ => 0L
      }
      let shape = x.top()
      let items = self
        .iterate(x, span)
        .mapi((i, el) => {
          value: VTuple([
            { value: VInt(start + i.to_int64()), label: shape, },
            el,
          ]),
          label: shape,
        })
      list_item(items, x.label, shape~)
    }
    "zip" => {
      let seqs = a.pos.map(x => self.iterate(x, span))
      let shape = a.pos.fold(init=plan, (acc, x) => acc.join(x.top()))
      let n = seqs.fold(init=self.world.limits.max_list, (m, s) => {
        m.min(s.length())
      })
      let items = Array::makei(if seqs.is_empty() { 0 } else { n }, i => {
        value: VTuple(seqs.map(s => s[i])),
        label: shape,
      })
      list_item(items, shape)
    }
    "reversed" => {
      arity(1)
      let items = self.iterate(a.pos[0], span).rev()
      list_item(items, a.pos[0].label, shape=a.pos[0].top())
    }
    "sorted" => {
      arity(1)
      let x = a.pos[0]
      let items = self.iterate(x, span)
      let key_fn = a.kwarg("key")
      let rev = match a.kwarg("reverse") {
        Some(r) => r.value.truthy()
        None => false
      }
      let keyed = items.map(el => {
        let k = match key_fn {
          Some(f) => self.apply(f, { pos: [el], kw: [], }, span)
          None => el
        }
        (k, el)
      })
      let mut order_label = x.top()
      for p in keyed {
        order_label = order_label.join(p.0.deep())
      }
      let mut failure : PlanError? = None
      keyed.sort_by((p, q) => {
        match values_compare(p.0.value, q.0.value) {
          Some(c) => if rev { -c } else { c }
          None => {
            if failure is None {
              failure = Some(
                type_error(
                  "'<' not supported between instances of '\{p.0.value.type_name()}' and '\{q.0.value.type_name()}'",
                  span,
                ),
              )
            }
            0
          }
        }
      })
      if failure is Some(e) {
        raise e
      }
      // The order of the result depends on every key.
      list_item(keyed.map(p => p.1), x.label, shape=order_label)
    }
    "sum" => {
      let x = match a.pos {
        [x] | [x, _] => x
        _ => raise type_error("sum() takes 1 or 2 arguments", span)
      }
      let mut acc = match a.pos.get(1) {
        Some(s) => s
        None => { value: VInt(0L), label: plan, }
      }
      for el in self.iterate(x, span) {
        acc = self.binop(Add, acc, el, span)
      }
      acc.taint(x.top())
    }
    "min" | "max" => {
      // Whether the sequence is empty is part of its shape: when the default
      // is returned, that choice was made by the shape.
      let emptiness = match a.pos {
        [x] => x.top()
        _ => Label::bottom()
      }
      let candidates = match a.pos {
        [x] => self.iterate(x, span).map(el => el.taint(x.top()))
        xs => xs
      }
      if candidates.is_empty() {
        match a.kwarg("default") {
          Some(d) => return d.taint(emptiness)
          None =>
            raise err(
              Runtime("ValueError"),
              "\{name}() arg is an empty sequence",
              span,
              label=emptiness,
            )
        }
      }
      let key_fn = a.kwarg("key")
      let key = fn(el : Item) -> Item raise PlanError {
        match key_fn {
          Some(f) => self.apply(f, { pos: [el], kw: [], }, span)
          None => el
        }
      }
      let mut best = candidates[0]
      let mut best_key = key(best)
      let mut used = best_key.deep()
      for el in candidates[1:] {
        let k = key(el)
        used = used.join(k.deep())
        let c = match values_compare(k.value, best_key.value) {
          Some(c) => c
          None =>
            raise type_error(
              "'\{name}' not supported between these values",
              span,
            )
        }
        if (name == "min" && c < 0) || (name == "max" && c > 0) {
          best = el
          best_key = k
        }
      }
      best.taint(used)
    }
    "abs" => {
      arity(1)
      let x = a.pos[0]
      match x.value {
        VInt(i) => { value: VInt(i.abs()), label: x.label, }
        VFloat(f) => { value: VFloat(f.abs()), label: x.label, }
        other =>
          raise type_error(
            "bad operand type for abs(): '\{other.type_name()}'",
            span,
          )
      }
    }
    "round" => {
      let x = match a.pos.get(0) {
        Some(x) => x
        None => raise type_error("round() needs a number", span)
      }
      let digits = match a.pos.get(1) {
        Some({ value: VInt(d), .. }) => Some(d.to_int())
        _ => None
      }
      let l = a.pos.fold(init=Label::bottom(), (acc, y) => acc.join(y.label))
      match (as_number(x.value), digits) {
        (Some(n), None) =>
          { value: VInt(round_half_even(n).to_int64()), label: l, }
        (Some(n), Some(d)) => {
          let scale = @math.pow(10.0, d.to_double())
          { value: VFloat(round_half_even(n * scale) / scale), label: l, }
        }
        _ =>
          raise type_error(
            "type \{x.value.type_name()} doesn't define __round__",
            span,
          )
      }
    }
    "any" | "all" => {
      arity(1)
      let x = a.pos[0]
      let mut used = x.top()
      let want = name == "any"
      for el in self.iterate(x, span) {
        used = used.join(el.deep())
        if el.value.truthy() == want {
          return { value: VBool(want), label: used, }
        }
      }
      { value: VBool(!want), label: used, }
    }
    "isinstance" => {
      arity(2)
      let x = a.pos[0]
      let ok = match a.pos[1].value {
        VClass(BuiltinType(t)) => x.value.type_name() == t
        VClass(RecordType(t)) => x.value.type_name() == t
        VTuple(ts) =>
          ts
          .iter()
          .any(t => {
            match t.value {
              VClass(BuiltinType(n)) | VClass(RecordType(n)) =>
                x.value.type_name() == n
              _ => false
            }
          })
        _ => raise type_error("isinstance() arg 2 must be a type", span)
      }
      { value: VBool(ok), label: x.label, }
    }
    "type" => {
      arity(1)
      str_item(a.pos[0].value.type_name(), a.pos[0].label)
    }
    _ => raise err(Runtime("NameError"), "name '\{name}' is not defined", span)
  }
}

///|
/// Python's `round` (banker's rounding).
fn round_half_even(x : Double) -> Double {
  let f = x.floor()
  let diff = x - f
  if diff > 0.5 {
    f + 1.0
  } else if diff < 0.5 {
    f
  } else if (f / 2.0).floor() * 2.0 == f {
    f
  } else {
    f + 1.0
  }
}
