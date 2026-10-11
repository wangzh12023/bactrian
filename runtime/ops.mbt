///|
fn Ctx::binop(
  self : Ctx,
  op : @ast.Operator,
  l : Item,
  r : Item,
  span : @basic.Span,
) -> Item raise PlanError {
  // The result of combining two values depends on everything in both.
  let lbl = l.deep().join(r.deep())
  let bad = fn() -> PlanError {
    type_error(
      "unsupported operand type(s) for \{op.symbol()}: '\{l.value.type_name()}' and '\{r.value.type_name()}'",
      span,
    )
  }
  match (op, l.value, r.value) {
    (Add, VStr(a), VStr(b)) => { value: VStr(a + b), label: lbl, }
    (Add, VList(a), VList(b)) => {
      let items = [
        ..a.items.map(x => x.taint(l.label)),
        ..b.items.map(x => x.taint(r.label)),
      ]
      list_item(items, l.label.join(r.label), shape=l.top().join(r.top()))
    }
    (Add, VTuple(a), VTuple(b)) => { value: VTuple([..a, ..b]), label: lbl, }
    (Mult, VStr(s), VInt(n)) | (Mult, VInt(n), VStr(s)) => {
      if n > 10000L {
        raise err(Budget, "string repetition is too large", span)
      }
      { value: VStr(s.repeat(n.to_int().max(0))), label: lbl, }
    }
    (Mult, VList(a), VInt(n)) | (Mult, VInt(n), VList(a)) => {
      if n.to_int() * a.items.length() > self.world.limits.max_list {
        raise err(Budget, "list repetition is too large", span)
      }
      let items = []
      for _ in 0..<n.to_int().max(0) {
        items.append(a.items)
      }
      list_item(items, lbl)
    }
    (Mod, VStr(_), _) =>
      raise unsupported(
        "`%` formatting is not available; use an f-string", span,
      )
    (_, VInt(a), VInt(b)) =>
      match op {
        Add => { value: VInt(a + b), label: lbl, }
        Sub => { value: VInt(a - b), label: lbl, }
        Mult => { value: VInt(a * b), label: lbl, }
        Div => {
          if b == 0L {
            raise err(
              Runtime("ZeroDivisionError"),
              "division by zero",
              span,
              label=lbl,
            )
          }
          { value: VFloat(a.to_double() / b.to_double()), label: lbl, }
        }
        FloorDiv => {
          if b == 0L {
            raise err(
              Runtime("ZeroDivisionError"),
              "integer division by zero",
              span,
              label=lbl,
            )
          }
          { value: VInt(floor_div(a, b)), label: lbl, }
        }
        Mod => {
          if b == 0L {
            raise err(
              Runtime("ZeroDivisionError"),
              "integer modulo by zero",
              span,
              label=lbl,
            )
          }
          { value: VInt(a - floor_div(a, b) * b), label: lbl, }
        }
        Pow =>
          if b >= 0L {
            {
              value: VInt(@math.pow(a.to_double(), b.to_double()).to_int64()),
              label: lbl,
            }
          } else {
            {
              value: VFloat(@math.pow(a.to_double(), b.to_double())),
              label: lbl,
            }
          }
        BitAnd => { value: VInt(a & b), label: lbl, }
        BitOr => { value: VInt(a | b), label: lbl, }
        BitXor => { value: VInt(a ^ b), label: lbl, }
        _ => raise bad()
      }
    (_, a, b) =>
      match (as_number(a), as_number(b)) {
        (Some(x), Some(y)) =>
          match op {
            Add => { value: VFloat(x + y), label: lbl, }
            Sub => { value: VFloat(x - y), label: lbl, }
            Mult => { value: VFloat(x * y), label: lbl, }
            Div => {
              if y == 0.0 {
                raise err(
                  Runtime("ZeroDivisionError"),
                  "float division by zero",
                  span,
                  label=lbl,
                )
              }
              { value: VFloat(x / y), label: lbl, }
            }
            FloorDiv => {
              if y == 0.0 {
                raise err(
                  Runtime("ZeroDivisionError"),
                  "float floor division by zero",
                  span,
                  label=lbl,
                )
              }
              { value: VFloat((x / y).floor()), label: lbl, }
            }
            Mod => {
              if y == 0.0 {
                raise err(
                  Runtime("ZeroDivisionError"),
                  "float modulo",
                  span,
                  label=lbl,
                )
              }
              { value: VFloat(x - (x / y).floor() * y), label: lbl, }
            }
            Pow => { value: VFloat(@math.pow(x, y)), label: lbl, }
            _ => raise bad()
          }
        _ => raise bad()
      }
  }
}

///|
fn floor_div(a : Int64, b : Int64) -> Int64 {
  let q = a / b
  if a % b != 0L && (a < 0L) != (b < 0L) {
    q - 1L
  } else {
    q
  }
}

///|
/// Evaluates one comparison. Returns the result and the label of the data it
/// depended on.
fn Ctx::compare(
  self : Ctx,
  op : @ast.CmpOp,
  l : Item,
  r : Item,
  span : @basic.Span,
) -> (Bool, Label) raise PlanError {
  ignore(self)
  match op {
    In | NotIn => {
      let (found, used) = contains(r, l, span)
      ((op is In) == found, used.join(l.deep()))
    }
    _ => {
      let used = l.deep().join(r.deep())
      let ordering = fn() -> Int raise PlanError {
        match values_compare(l.value, r.value) {
          Some(c) => c
          None =>
            raise type_error(
              "'\{op.symbol()}' not supported between instances of '\{l.value.type_name()}' and '\{r.value.type_name()}'",
              span,
            )
        }
      }
      let res = match op {
        Eq => values_equal(l.value, r.value)
        NotEq => !values_equal(l.value, r.value)
        Is => same_identity(l.value, r.value)
        IsNot => !same_identity(l.value, r.value)
        Lt => ordering() < 0
        LtE => ordering() <= 0
        Gt => ordering() > 0
        GtE => ordering() >= 0
        In | NotIn => false
      }
      (res, used)
    }
  }
}

///|
fn same_identity(a : Value, b : Value) -> Bool {
  match (a, b) {
    (VNone, VNone) => true
    (VBool(x), VBool(y)) => x == y
    (VList(x), VList(y)) => physical_equal(x, y)
    (VDict(x), VDict(y)) => physical_equal(x, y)
    _ => values_equal(a, b)
  }
}

///|
/// Membership test. A negative answer reveals something about every element,
/// a positive one about the elements up to the match and the container's
/// shape (CaMeL's "False reveals something about all of them").
fn contains(
  container : Item,
  needle : Item,
  span : @basic.Span,
) -> (Bool, Label) raise PlanError {
  match container.value {
    VStr(hay) =>
      match needle.value {
        VStr(n) => (hay.contains(n), container.label)
        other =>
          raise type_error(
            "'in <string>' requires string as left operand, not \{other.type_name()}",
            span,
          )
      }
    VList(_) | VTuple(_) => {
      let items = match container.value {
        VList(l) => l.items
        VTuple(xs) => xs
        _ => []
      }
      let mut used = container.top()
      for x in items {
        used = used.join(x.deep())
        if values_equal(x.value, needle.value) {
          return (true, used)
        }
      }
      (false, used)
    }
    VDict(d) =>
      match key_of(needle.value) {
        Some(k) => {
          // Which keys exist is the dict's shape.
          let used = container
            .top()
            .join(
              match d.entries.get(k) {
                Some((key, _)) => key.label
                None => Label::bottom()
              },
            )
          (d.entries.contains(k), used)
        }
        None => (false, container.top())
      }
    VRecord(r) =>
      match needle.value {
        VStr(n) => (r.fields.contains(n), container.label)
        _ => (false, container.label)
      }
    other =>
      raise type_error(
        "argument of type '\{other.type_name()}' is not iterable",
        span,
      )
  }
}

///|
fn Ctx::attribute(
  self : Ctx,
  obj : Item,
  attr : String,
  span : @basic.Span,
) -> Item raise PlanError {
  match obj.value {
    VRecord(r) =>
      match r.fields.get(attr) {
        Some(v) => v.taint(obj.label)
        None =>
          if method_exists(obj.value, attr) {
            { value: VFunc(Method(obj, attr)), label: obj.label, }
          } else {
            raise err(
              Runtime("AttributeError"),
              "'\{r.type_name}' object has no attribute '\{attr}'",
              span,
            )
          }
      }
    _ =>
      if method_exists(obj.value, attr) {
        { value: VFunc(Method(obj, attr)), label: obj.label, }
      } else {
        raise err(
          Runtime("AttributeError"),
          "'\{obj.value.type_name()}' object has no attribute '\{attr}'",
          span,
        )
      }
  }
}

///|
fn Ctx::subscript(
  self : Ctx,
  obj : Item,
  key : Item,
  span : @basic.Span,
) -> Item raise PlanError {
  // Which element is read depends on the key; whether it exists depends on
  // the container's shape.
  let via = obj.label.join(key.label)
  match obj.value {
    VList(l) => {
      let i = self.index_of(key, l.items.length(), span)
      l.items[i].taint(via.join(l.shape))
    }
    VTuple(xs) => {
      let i = self.index_of(key, xs.length(), span)
      xs[i].taint(via)
    }
    VStr(s) => {
      let chars = s.to_array()
      let i = self.index_of(key, chars.length(), span)
      str_item(chars[i].to_string(), via)
    }
    VDict(d) =>
      match key_of(key.value) {
        Some(k) =>
          match d.entries.get(k) {
            // Which value sits under a key may have been decided by a write
            // through another key: the read depends on the dict's shape.
            Some((_, v)) => v.taint(via.join(d.shape))
            None =>
              raise err(
                Runtime("KeyError"),
                key.value.repr(),
                span,
                label=key.label.join(d.shape),
              )
          }
        None =>
          raise type_error("unhashable type: '\{key.value.type_name()}'", span)
      }
    VRecord(r) =>
      match key.value {
        VStr(name) if r.fields.contains(name) => r.fields[name].taint(via)
        _ =>
          raise type_error(
            "'\{r.type_name}' object is not subscriptable; use `.field`",
            span,
          )
      }
    other =>
      raise type_error(
        "'\{other.type_name()}' object is not subscriptable",
        span,
      )
  }
}

///|
fn Ctx::slice(
  self : Ctx,
  obj : Item,
  lower : @ast.Expr?,
  upper : @ast.Expr?,
  step : @ast.Expr?,
  span : @basic.Span,
) -> Item raise PlanError {
  let bound = fn(e : @ast.Expr?) -> (Int?, Label) raise PlanError {
    match e {
      None => (None, Label::bottom())
      Some(x) =>
        match self.eval(x) {
          { value: VInt(i), label, } => (Some(i.to_int()), label)
          { value: VNone, label, } => (None, label)
          other =>
            raise type_error(
              "slice indices must be integers, not '\{other.value.type_name()}'",
              span,
            )
        }
    }
  }
  let (lo, l1) = bound(lower)
  let (hi, l2) = bound(upper)
  let (st, l3) = bound(step)
  let st = st.unwrap_or(1)
  if st == 0 {
    raise err(Runtime("ValueError"), "slice step cannot be zero", span)
  }
  let via = obj.label.join(l1).join(l2).join(l3)
  let pick = fn(n : Int) -> Array[Int] {
    let norm = fn(i : Int?, default : Int) -> Int {
      match i {
        None => default
        Some(i) => {
          let j = if i < 0 { i + n } else { i }
          if st > 0 {
            j.max(0).min(n)
          } else {
            j.max(-1).min(n - 1)
          }
        }
      }
    }
    let out = []
    if st > 0 {
      let mut i = norm(lo, 0)
      let stop = norm(hi, n)
      while i < stop {
        out.push(i)
        i += st
      }
    } else {
      let mut i = norm(lo, n - 1)
      let stop = norm(hi, -1)
      while i > stop {
        out.push(i)
        i += st
      }
    }
    out
  }
  match obj.value {
    VList(l) =>
      list_item(
        pick(l.items.length()).map(i => l.items[i]),
        via,
        shape=via.join(l.shape),
      )
    VTuple(xs) =>
      { value: VTuple(pick(xs.length()).map(i => xs[i])), label: via, }
    VStr(s) => {
      let chars = s.to_array()
      str_item(String::from_array(pick(chars.length()).map(i => chars[i])), via)
    }
    other =>
      raise type_error(
        "'\{other.type_name()}' object is not subscriptable",
        span,
      )
  }
}
