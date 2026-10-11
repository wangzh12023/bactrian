///|
/// The builtin functions available to plans.
let builtin_functions : Array[String] = [
  "abs", "all", "any", "bool", "dict", "enumerate", "float", "int", "isinstance",
  "len", "list", "max", "min", "print", "range", "repr", "reversed", "round", "set",
  "sorted", "str", "sum", "tuple", "type", "zip",
]

///|
/// Names that are always in scope.
fn is_builtin_name(name : String) -> Bool {
  builtin_functions.contains(name) ||
  name
  is ("True"
  | "False"
  | "None"
  | "BaseModel"
  | "TypedDict"
  | "dataclass"
  | "Field"
  | "EmailStr") ||
  error_types.contains(name)
}

///|
let error_types : Array[String] = [
  "Exception", "ValueError", "TypeError", "KeyError", "IndexError", "RuntimeError",
  "AssertionError", "NotEnoughInformationError",
]

///|
fn Ctx::eval(self : Ctx, e : @ast.Expr) -> Item raise PlanError {
  self.tick(e.span())
  match e {
    Constant(value~, span~) => self.constant(value, span)
    Name(id~, span~, ..) => self.load_name(id, span)
    JoinedStr(parts~, ..) => {
      let sb = StringBuilder()
      let mut l = Label::bottom()
      for p in parts {
        match p {
          Text(t) => sb.write_string(t)
          Hole(value~, conversion~, spec~) => {
            let v = self.eval(value)
            l = l.join(v.deep())
            let text = match conversion {
              Some('r') => v.value.repr()
              _ => v.value.to_str()
            }
            sb.write_string(apply_format_spec(text, v.value, spec))
          }
        }
      }
      { value: VStr(sb.to_string()), label: l.join(Label::plan()), }
    }
    List(elts~, span~, ..) => {
      let (items, spread) = self.eval_elements(elts, span)
      list_item(items, Label::plan(), shape=Label::plan().join(spread))
    }
    Tuple(elts~, span~, ..) => {
      let (items, spread) = self.eval_elements(elts, span)
      { value: VTuple(items), label: Label::plan().join(spread), }
    }
    Set(elts~, span~) => {
      let (items, spread) = self.eval_elements(elts, span)
      list_item(dedupe(items), Label::plan(), shape=Label::plan().join(spread))
    }
    Dict(keys~, values~, span~) => {
      let entries : Map[String, (Item, Item)] = Map([])
      let mut shape = Label::plan()
      for i, k in keys {
        match k {
          Some(ke) => {
            let key = self.eval(ke)
            let v = self.eval(values[i])
            match key_of(key.value) {
              Some(kk) => entries[kk] = (key, v)
              None =>
                raise type_error(
                  "unhashable type: '\{key.value.type_name()}'",
                  span,
                )
            }
            shape = shape.join(key.label)
          }
          None =>
            // `**other`
            match self.eval(values[i]) {
              { value: VDict(d), label, } => {
                shape = shape.join(label).join(d.shape)
                for kk, kv in d.entries {
                  entries[kk] = (kv.0.taint(label), kv.1.taint(label))
                }
              }
              other =>
                raise type_error(
                  "'\{other.value.type_name()}' object is not a mapping",
                  span,
                )
            }
        }
      }
      { value: VDict({ entries, shape, }), label: Label::plan(), }
    }
    Attribute(value~, attr~, span~, ..) =>
      self.attribute(self.eval(value), attr, span)
    Subscript(value~, slice~, span~, ..) => {
      let container = self.eval(value)
      match slice {
        Slice(lower~, upper~, step~, ..) =>
          self.slice(container, lower, upper, step, span)
        _ => self.subscript(container, self.eval(slice), span)
      }
    }
    BinOp(left~, op~, right~, span~) => {
      let l = self.eval(left)
      let r = self.eval(right)
      self.binop(op, l, r, span)
    }
    UnaryOp(op~, operand~, span~) => {
      let v = self.eval(operand)
      let l = v.top()
      match (op, v.value) {
        (Not, x) => { value: VBool(!x.truthy()), label: l, }
        (USub, VInt(i)) => { value: VInt(-i), label: l, }
        (USub, VFloat(f)) => { value: VFloat(-f), label: l, }
        (USub, VBool(b)) => { value: VInt(if b { -1L } else { 0L }), label: l, }
        (UAdd, VInt(_) | VFloat(_) as x) => { value: x, label: l, }
        (Invert, VInt(i)) => { value: VInt(i.lnot()), label: l, }
        (_, x) =>
          raise type_error(
            "bad operand type for unary \{op.symbol()}: '\{x.type_name()}'",
            span,
            label=l,
          )
      }
    }
    BoolOp(op~, values~, ..) => {
      // Short-circuit: which operand is returned depends on the truthiness
      // of every operand evaluated before it.
      let mut decided = Label::bottom()
      let mut result : Item? = None
      for v in values {
        let x = self.with_pc(decided).eval(v)
        result = Some(x)
        let stop = match op {
          And => !x.value.truthy()
          Or => x.value.truthy()
        }
        if stop {
          break
        }
        decided = decided.join(x.top())
      }
      match result {
        Some(x) => x.taint(decided)
        None => none_item(Label::plan())
      }
    }
    Compare(left~, ops~, comparators~, span~) => {
      let mut lhs = self.eval(left)
      let mut l = Label::bottom()
      let mut ok = true
      for i, op in ops {
        let rhs = self.eval(comparators[i])
        let (res, used) = self.compare(op, lhs, rhs, span)
        l = l.join(used)
        if !res {
          ok = false
          break
        }
        lhs = rhs
      }
      { value: VBool(ok), label: l, }
    }
    IfExp(cond~, body~, or_else~, ..) => {
      let c = self.eval(cond)
      let inner = self.with_pc(c.top())
      let v = if c.value.truthy() {
        inner.eval(body)
      } else {
        inner.eval(or_else)
      }
      v.taint(c.top())
    }
    NamedExpr(target~, value~, ..) => {
      let v = self.eval(value)
      self.assign(target, v)
      v
    }
    Call(func~, args~, keywords~, span~) =>
      self.call(func, args, keywords, span)
    ListComp(elt~, generators~, span~) => {
      let out = []
      let shape = self.comprehension(
        generators,
        0,
        Map([]),
        Label::bottom(),
        span,
        (ctx, local_pc) => out.push(ctx.eval(elt).taint(local_pc)),
      )
      list_item(out, Label::plan(), shape~)
    }
    SetComp(elt~, generators~, span~) => {
      let out = []
      let shape = self.comprehension(
        generators,
        0,
        Map([]),
        Label::bottom(),
        span,
        (ctx, local_pc) => out.push(ctx.eval(elt).taint(local_pc)),
      )
      list_item(dedupe(out), Label::plan(), shape~)
    }
    GeneratorExp(elt~, generators~, span~) => {
      // Generators are evaluated eagerly; `any(x for x in xs)` works as in
      // Python, minus laziness.
      let out = []
      let shape = self.comprehension(
        generators,
        0,
        Map([]),
        Label::bottom(),
        span,
        (ctx, local_pc) => out.push(ctx.eval(elt).taint(local_pc)),
      )
      list_item(out, Label::plan(), shape~)
    }
    DictComp(key~, value~, generators~, span~) => {
      let entries : Map[String, (Item, Item)] = Map([])
      let mut key_labels = Label::bottom()
      let shape = self.comprehension(
        generators,
        0,
        Map([]),
        Label::bottom(),
        span,
        (ctx, local_pc) => {
          let k = ctx.eval(key).taint(local_pc)
          let v = ctx.eval(value).taint(local_pc)
          match key_of(k.value) {
            Some(kk) => entries[kk] = (k, v)
            None =>
              raise type_error(
                "unhashable type: '\{k.value.type_name()}'",
                span,
              )
          }
          key_labels = key_labels.join(k.label)
        },
      )
      {
        value: VDict({ entries, shape: shape.join(key_labels), }),
        label: Label::plan(),
      }
    }
    Lambda(args~, body~, span~) => {
      if args.vararg is Some(_) ||
        args.kwarg is Some(_) ||
        !args.kwonlyargs.is_empty() ||
        !args.defaults.is_empty() {
        raise unsupported(
          "lambdas may only take plain positional parameters", span,
        )
      }
      // Lambdas must be pure: a hidden write would escape the static
      // analysis that keeps control-flow labels sound.
      let writes = []
      expr_writes(body, writes)
      if !writes.is_empty() {
        raise unsupported(
          "lambdas must not modify anything (found a write to `\{writes[0]}`)",
          span,
        )
      }
      let params = [..args.posonlyargs, ..args.args].map(a => a.arg)
      {
        value: VFunc(Lambda({ params, body, scopes: self.scopes.copy(), })),
        label: Label::plan(),
      }
    }
    Starred(span~, ..) =>
      raise unsupported(
        "`*` is only allowed inside list, tuple and call literals", span,
      )
    Slice(span~, ..) => raise unsupported("a slice outside of `[...]`", span)
    Await(span~, ..) | Yield(span~, ..) | YieldFrom(span~, ..) =>
      raise unsupported("`await`/`yield` are not available", span)
  }
}

///|
fn Ctx::constant(
  _ : Ctx,
  c : @ast.Constant,
  span : @basic.Span,
) -> Item raise PlanError {
  let l = Label::plan()
  match c {
    Int(b) => {
      let i = b.to_int64()
      if @bigint.BigInt::from_int64(i) != b {
        raise unsupported("integer literal out of range", span)
      }
      { value: VInt(i), label: l, }
    }
    Float(f) => { value: VFloat(f), label: l, }
    Str(s) => { value: VStr(s), label: l, }
    Bool(b) => { value: VBool(b), label: l, }
    None => { value: VNone, label: l, }
    Complex(_) | Bytes(_) | Ellipsis =>
      raise unsupported("\{c.type_name()} literals are not available", span)
  }
}

///|
fn Ctx::load_name(
  self : Ctx,
  id : String,
  span : @basic.Span,
) -> Item raise PlanError {
  match self.lookup(id) {
    Some(v) => v
    None => {
      let l = Label::plan()
      if self.world.tools.contains(id) {
        { value: VFunc(Tool(id)), label: l, }
      } else if id == "query_ai_assistant" {
        { value: VFunc(Builtin(id)), label: l, }
      } else if builtin_functions.contains(id) {
        match id {
          "str"
          | "int"
          | "float"
          | "bool"
          | "list"
          | "dict"
          | "tuple"
          | "set" => { value: VClass(BuiltinType(id)), label: l, }
          _ => { value: VFunc(Builtin(id)), label: l, }
        }
      } else if error_types.contains(id) {
        { value: VClass(ErrorType(id)), label: l, }
      } else if self.world.types.contains(id) ||
        self.session.plan_types.contains(id) {
        { value: VClass(RecordType(id)), label: l, }
      } else {
        match id {
          "True" => { value: VBool(true), label: l, }
          "False" => { value: VBool(false), label: l, }
          "None" => { value: VNone, label: l, }
          _ =>
            raise err(Runtime("NameError"), "name '\{id}' is not defined", span)
        }
      }
    }
  }
}

///|
/// Evaluates list/tuple/set elements, expanding `*xs`. Returns the elements
/// and the join of the shapes of every spread iterable: how many elements a
/// `*xs` contributes, and in which order, depends on `xs`, so the length and
/// order of the result do too.
fn Ctx::eval_elements(
  self : Ctx,
  elts : Array[@ast.Expr],
  span : @basic.Span,
) -> (Array[Item], Label) raise PlanError {
  let out = []
  let mut spread = Label::bottom()
  for e in elts {
    match e {
      Starred(value~, ..) => {
        let v = self.eval(value)
        spread = spread.join(v.top())
        for x in self.iterate(v, span) {
          out.push(x.taint(v.top()))
        }
      }
      _ => out.push(self.eval(e))
    }
    if out.length() > self.world.limits.max_list {
      raise err(
        Budget,
        "a list grew beyond \{self.world.limits.max_list} elements",
        span,
      )
    }
  }
  (out, spread)
}

///|
/// Runs the generators of a comprehension, calling `emit` for every
/// combination that passes the filters. `local_pc` is the label of everything
/// that decided whether this element exists (iterables and filters); the
/// returned label is the join of all of them: it decides the result's shape.
fn Ctx::comprehension(
  self : Ctx,
  gens : Array[@ast.Comprehension],
  i : Int,
  scope : Map[String, Item],
  local_pc : Label,
  span : @basic.Span,
  emit : (Ctx, Label) -> Unit raise PlanError,
) -> Label raise PlanError {
  let ctx = self.with_scope(scope)
  if i >= gens.length() {
    emit(ctx, local_pc)
    return local_pc
  }
  let g = gens[i]
  if g.is_async {
    raise unsupported("async comprehensions", span)
  }
  let seq = ctx.with_pc(local_pc).eval(g.iter)
  let mut shape = local_pc.join(seq.top())
  for el in ctx.iterate(seq, span) {
    self.tick(span)
    let inner_scope = scope.copy()
    let inner = self.with_scope(inner_scope).with_pc(shape)
    inner.assign(g.target, el)
    let mut keep = true
    let mut filter_label = Label::bottom()
    for cond in g.ifs {
      let c = inner.with_pc(filter_label).eval(cond)
      filter_label = filter_label.join(c.top())
      if !c.value.truthy() {
        keep = false
        break
      }
    }
    shape = shape.join(filter_label)
    if keep {
      shape = shape.join(
        self.comprehension(
          gens,
          i + 1,
          inner_scope,
          local_pc.join(seq.top()).join(filter_label),
          span,
          emit,
        ),
      )
    }
  }
  shape
}

///|
/// Removes duplicates (used for sets), keeping the first occurrence.
fn dedupe(items : Array[Item]) -> Array[Item] {
  let seen : Map[String, Unit] = Map([])
  let out = []
  for x in items {
    match key_of(x.value) {
      Some(k) =>
        if !seen.contains(k) {
          seen[k] = ()
          out.push(x)
        }
      None => out.push(x)
    }
  }
  out
}

///|
/// A small subset of Python's format mini-language: `.2f`, `d`, `,`, width.
fn apply_format_spec(text : String, v : Value, spec : String?) -> String {
  match spec {
    None | Some("") => text
    Some(s) => {
      let (body, kind) = match s.strip_suffix("f") {
        Some(b) => (b.to_owned(), 'f')
        None =>
          match s.strip_suffix("d") {
            Some(b) => (b.to_owned(), 'd')
            None => (s, ' ')
          }
      }
      let comma = body.contains(",")
      let precision = match body.find(".") {
        Some(i) => @string.parse_int(body[i + 1:]) catch { _ => 6 }
        None => 6
      }
      let formatted = match (kind, as_number(v)) {
        ('f', Some(n)) => fixed(n, precision)
        ('d', Some(n)) => n.to_int64().to_string()
        _ => text
      }
      if comma {
        group_thousands(formatted)
      } else {
        formatted
      }
    }
  }
}

///|
/// Formats `n` with exactly `digits` digits after the point.
fn fixed(n : Double, digits : Int) -> String {
  let digits = if digits < 0 { 0 } else if digits > 12 { 12 } else { digits }
  let scale = @math.pow(10.0, digits.to_double())
  let neg = n < 0.0
  let scaled = (n.abs() * scale).round()
  let int_part = (scaled / scale).floor()
  let frac = scaled - int_part * scale
  let int_text = int_part.to_int64().to_string()
  if digits == 0 {
    return (if neg && scaled != 0.0 { "-" } else { "" }) + int_text
  }
  let frac_text = frac.to_int64().to_string().pad_start(digits, '0')
  (if neg && scaled != 0.0 { "-" } else { "" }) + int_text + "." + frac_text
}

///|
fn group_thousands(s : String) -> String {
  let (sign, rest) = if s.has_prefix("-") {
    ("-", s[1:].to_owned())
  } else {
    ("", s)
  }
  let (int_part, frac) = match rest.split_once(".") {
    Some((a, b)) => (a.to_owned(), "." + b.to_owned())
    None => (rest, "")
  }
  let chars = int_part.to_array()
  let sb = StringBuilder()
  for i, c in chars {
    if i > 0 && (chars.length() - i) % 3 == 0 {
      sb.write_char(',')
    }
    sb.write_char(c)
  }
  sign + sb.to_string() + frac
}
