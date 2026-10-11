///|
/// Evaluation context.
///
/// `pc` is the label of the control context: everything that decided that
/// execution reached this point. Under STRICT semantics every value created
/// or assigned here is joined with `pc`, and every tool call reports it to the
/// policy. `exit` accumulates, for the innermost loop, the labels of every
/// condition that may `break` or `continue` it: later iterations run only
/// because those conditions did not fire.
priv struct Ctx {
  world : World
  session : Session
  /// Responses to effects performed so far.
  memo : Memo
  /// How many times each effect identity has been requested in this run.
  seen : Map[String, Int]
  /// Innermost scope last. Comprehension and lambda scopes are pushed on top
  /// of the globals.
  scopes : Array[Map[String, Item]]
  pc : Label
  exit : Ref[Label]
  strict : Bool
}

///|
/// Returns the recorded response to `effect`, or suspends the run so the
/// driver can perform it.
fn Ctx::effect(
  self : Ctx,
  effect : Effect,
  span : @basic.Span,
) -> Response raise PlanError {
  let identity = effect.identity()
  let n = self.seen.get(identity).unwrap_or(0)
  self.seen[identity] = n + 1
  match self.memo.get("\{n}|\{identity}") {
    Some(r) => r
    None => raise err(Pending(effect), "waiting for the host", span)
  }
}

///|
fn Ctx::with_pc(self : Ctx, extra : Label) -> Ctx {
  { ..self, pc: self.pc.join(extra), }
}

///|
fn Ctx::with_scope(self : Ctx, scope : Map[String, Item]) -> Ctx {
  { ..self, scopes: [..self.scopes, scope], }
}

///|
fn Ctx::tick(self : Ctx, span : @basic.Span) -> Unit raise PlanError {
  self.session.steps += 1
  if self.session.steps > self.world.limits.max_steps {
    raise err(
      Budget,
      "the plan took more than \{self.world.limits.max_steps} steps",
      span,
    )
  }
}

///|
fn Ctx::lookup(self : Ctx, name : String) -> Item? {
  for i = self.scopes.length() - 1; i >= 0; i = i - 1 {
    if self.scopes[i].get(name) is Some(v) {
      return Some(v)
    }
  }
  self.session.globals.get(name)
}

///|
/// Binds `name` in the innermost scope (the globals at top level).
fn Ctx::assign_name(self : Ctx, name : String, item : Item) -> Unit {
  // A variable written here reveals that execution reached this point.
  let it = item.taint(self.flow())
  match self.scopes.last() {
    Some(scope) => scope[name] = it
    None => self.session.globals[name] = it
  }
}

///|
/// The label that data written at this point must carry: the control
/// context under STRICT semantics, nothing under NORMAL semantics.
fn Ctx::flow(self : Ctx) -> Label {
  if self.strict {
    self.pc
  } else {
    Label::bottom()
  }
}

///|
/// Joins `extra` into the binding of every listed variable and into the
/// shape of every container reachable from it.
///
/// This is how the interpreter accounts for *implicit* flows: when a branch
/// is not taken, the variables it would have written keep their old values,
/// and those values now reveal the branch condition.
fn Ctx::taint_vars(self : Ctx, names : Array[String], extra : Label) -> Unit {
  if extra.sources.is_empty() && extra.readers is Public {
    return
  }
  for name in names {
    let scope = for i = self.scopes.length() - 1; i >= 0; i = i - 1 {
      if self.scopes[i].contains(name) {
        break Some(self.scopes[i])
      }
    } nobreak {
      if self.session.globals.contains(name) {
        Some(self.session.globals)
      } else {
        None
      }
    }
    if scope is Some(scope) {
      let it = scope[name]
      taint_shapes(it, extra, [])
      scope[name] = it.taint(extra)
    }
  }
}

///|
/// Joins `extra` into the shape of every list and dict reachable from `it`.
fn taint_shapes(it : Item, extra : Label, seen : Array[Value]) -> Unit {
  match it.value {
    VList(l) => {
      if seen.iter().any(v => v is VList(o) && physical_equal(o, l)) {
        return
      }
      seen.push(it.value)
      l.shape = l.shape.join(extra)
      for x in l.items {
        taint_shapes(x, extra, seen)
      }
    }
    VDict(d) => {
      if seen.iter().any(v => v is VDict(o) && physical_equal(o, d)) {
        return
      }
      seen.push(it.value)
      d.shape = d.shape.join(extra)
      for kv in d.entries.values() {
        taint_shapes(kv.1, extra, seen)
      }
    }
    VTuple(xs) =>
      for x in xs {
        taint_shapes(x, extra, seen)
      }
    VRecord(r) =>
      for _, x in r.fields {
        taint_shapes(x, extra, seen)
      }
    _ => ()
  }
}

///|
/// The result of executing a statement list.
priv enum Flow {
  Normal
  /// `break` out of the innermost loop.
  Break
  /// `continue` the innermost loop.
  Continue
}

///|
fn Ctx::exec_block(
  self : Ctx,
  stmts : Array[@ast.Stmt],
) -> Flow raise PlanError {
  let mut ctx = self
  for s in stmts {
    match ctx.exec(s) {
      Normal => ()
      other => return other
    }
    // The rest of this block only runs because `s` did not leave the loop.
    if ctx.strict && may_exit_loop([s]) {
      ctx = ctx.with_pc(ctx.exit.val)
    }
  }
  Normal
}

///|
fn Ctx::exec(self : Ctx, stmt : @ast.Stmt) -> Flow raise PlanError {
  match stmt {
    ExprStmt(value~, ..) => {
      ignore(self.eval(value))
      Normal
    }
    Assign(targets~, value~, ..) => {
      let v = self.eval(value)
      for t in targets {
        self.assign(t, v)
      }
      Normal
    }
    AnnAssign(target~, value~, span~, ..) =>
      match value {
        Some(e) => {
          self.assign(target, self.eval(e))
          Normal
        }
        None => raise unsupported("a declaration without a value", span)
      }
    AugAssign(target~, op~, value~, span~) => {
      let current = self.eval(load_of(target))
      let rhs = self.eval(value)
      self.assign(target, self.binop(op, current, rhs, span))
      Normal
    }
    If(cond~, body~, or_else~, ..) => {
      let c = self.eval(cond)
      let decided = c.top()
      if may_exit_loop(body) || may_exit_loop(or_else) {
        self.exit.val = self.exit.val.join(decided)
      }
      let inner = self.with_pc(decided)
      let flow = if c.value.truthy() {
        inner.exec_block(body)
      } else {
        inner.exec_block(or_else)
      }
      // Whichever branch ran, the variables the other branch would have
      // written now reveal the condition.
      if self.strict {
        let written = []
        may_write(body, written)
        may_write(or_else, written)
        self.taint_vars(written, decided)
      }
      flow
    }
    For(target~, iter~, body~, or_else~, is_async~, span~) => {
      if is_async {
        raise unsupported("async for", span)
      }
      let seq = self.eval(iter)
      let elements = self.iterate(seq, span)
      // Whether the body runs, and how often, is decided by the iterable's
      // structure; whether a later iteration runs also depends on every
      // condition that could have ended the loop earlier.
      let decided = seq.top()
      let exit = Ref(Label::bottom())
      let inner = { ..self.with_pc(decided), exit, }
      let mut broke = false
      for el in elements {
        self.tick(span)
        let iteration = inner.with_pc(exit.val)
        iteration.assign(target, el)
        match iteration.exec_block(body) {
          Break => {
            broke = true
            break
          }
          Normal | Continue => ()
        }
      }
      if !broke && !or_else.is_empty() {
        ignore(inner.with_pc(exit.val).exec_block(or_else))
      }
      if self.strict {
        let written = []
        target_roots(target, written)
        may_write(body, written)
        may_write(or_else, written)
        self.taint_vars(written, decided.join(exit.val))
      }
      Normal
    }
    Pass(..) => Normal
    Break(..) => Break
    Continue(..) => Continue
    Raise(exc~, span~, ..) => {
      let (kind, message, label) = match exc {
        None => (Runtime("RuntimeError"), "re-raise", self.pc)
        Some(e) => {
          let v = self.eval(e)
          match v.value {
            VRecord({ type_name, fields, }) if fields.get("args") is Some(a) =>
              (Runtime(type_name), a.value.to_str(), v.deep().join(self.pc))
            VClass(ErrorType(name)) => (Runtime(name), "", self.pc)
            other =>
              (Runtime("Exception"), other.to_str(), v.deep().join(self.pc))
          }
        }
      }
      raise err(kind, message, span, label~)
    }
    ClassDef(name~, bases~, body~, decorators~, span~, ..) => {
      self.define_class(name, bases, body, decorators, span)
      Normal
    }
    ImportFrom(module_name~, names~, span~, ..) => {
      // `from pydantic import BaseModel` and the like are harmless; anything
      // that is not already available is refused.
      for a in names {
        if self.lookup(a.name) is None &&
          !is_builtin_name(a.name) &&
          !self.world.types.contains(a.name) {
          raise unsupported(
            "imports are not available; `\{a.name}` from `\{module_name.unwrap_or(".")}` is not provided",
            span,
          )
        }
      }
      Normal
    }
    Import(span~, ..) =>
      raise unsupported(
        "imports are not available: use only the tools and builtins you were given",
        span,
      )
    Assert(cond~, msg~, span~) => {
      let c = self.eval(cond)
      if !c.value.truthy() {
        let m = match msg {
          Some(e) => self.eval(e).value.to_str()
          None => "assertion failed"
        }
        raise err(
          Runtime("AssertionError"),
          m,
          span,
          label=c.top().join(self.pc),
        )
      }
      Normal
    }
    While(span~, ..) =>
      raise unsupported(
        "`while` loops are not available; use `for` over a list", span,
      )
    FunctionDef(span~, ..) =>
      raise unsupported(
        "defining functions is not available; write the steps inline or use a comprehension",
        span,
      )
    Try(span~, ..) =>
      raise unsupported(
        "`try` is not available: errors are reported to you automatically", span,
      )
    With(span~, ..) => raise unsupported("`with` is not available", span)
    Match(span~, ..) =>
      raise unsupported("`match` is not available; use `if`/`elif`", span)
    Delete(span~, ..) => raise unsupported("`del` is not available", span)
    Global(span~, ..) | Nonlocal(span~, ..) =>
      raise unsupported("`global`/`nonlocal` are not available", span)
    Return(span~, ..) =>
      raise unsupported("`return` is only allowed inside functions", span)
  }
}

///|
/// The expression that reads what `target` names (for augmented assignment).
fn load_of(target : @ast.Expr) -> @ast.Expr {
  @parser.set_context(target, Load)
}

///|
fn Ctx::assign(
  self : Ctx,
  target : @ast.Expr,
  item : Item,
) -> Unit raise PlanError {
  match target {
    Name(id~, span~, ..) => {
      if is_builtin_name(id) ||
        self.world.tools.contains(id) ||
        id == "query_ai_assistant" {
        raise unsupported(
          "`\{id}` is a builtin or a tool and cannot be reassigned",
          span,
        )
      }
      self.assign_name(id, item)
    }
    Tuple(elts~, span~, ..) | List(elts~, span~, ..) => {
      let parts = self.iterate(item, span)
      if parts.length() != elts.length() {
        raise err(
          Runtime("ValueError"),
          "cannot unpack \{parts.length()} values into \{elts.length()} names",
          span,
          label=item.top(),
        )
      }
      let structure = item.top()
      for i, e in elts {
        self.assign(e, parts[i].taint(structure))
      }
    }
    Subscript(value~, slice~, span~, ..) => {
      let container = self.eval(value)
      let key = self.eval(slice)
      let stored = item.taint(key.label.join(self.flow()))
      match container.value {
        VList(l) => {
          let i = self.index_of(key, l.items.length(), span)
          l.items[i] = stored
        }
        VDict(d) =>
          match key_of(key.value) {
            Some(k) => {
              if !d.entries.contains(k) {
                // Adding a key changes the dict's shape.
                d.shape = d.shape.join(key.label).join(self.flow())
              }
              d.entries[k] = (key, stored)
            }
            None =>
              raise type_error(
                "unhashable type: '\{key.value.type_name()}'",
                span,
              )
          }
        other =>
          raise type_error(
            "'\{other.type_name()}' object does not support item assignment",
            span,
          )
      }
    }
    Attribute(span~, ..) =>
      raise unsupported(
        "records are immutable; build a new value instead", span,
      )
    Starred(span~, ..) => raise unsupported("starred assignment", span)
    other =>
      raise unsupported("cannot assign to \{other.kind_name()}", other.span())
  }
}

///|
/// The elements of an iterable value, each joined with the iterable's
/// reference label. The shape (how many elements, in which order) is not
/// joined here: it is accounted for by the caller's `pc`.
fn Ctx::iterate(
  self : Ctx,
  seq : Item,
  span : @basic.Span,
) -> Array[Item] raise PlanError {
  ignore(self)
  let outer = seq.label
  match seq.value {
    VList(l) => l.items.map(x => x.taint(outer))
    VTuple(xs) => xs.map(x => x.taint(outer))
    VDict(d) => d.entries.values().map(kv => kv.0.taint(outer)).collect()
    VStr(s) => s.iter().map(c => str_item(c.to_string(), seq.label)).collect()
    VRecord(_)
    | VNone
    | VBool(_)
    | VInt(_)
    | VFloat(_)
    | VFunc(_)
    | VClass(_) =>
      raise type_error(
        "'\{seq.value.type_name()}' object is not iterable",
        span,
        label=seq.label,
      )
  }
}

///|
fn Ctx::index_of(
  self : Ctx,
  key : Item,
  length : Int,
  span : @basic.Span,
) -> Int raise PlanError {
  ignore(self)
  let i = match key.value {
    VInt(i) => i.to_int()
    VBool(b) => if b { 1 } else { 0 }
    other =>
      raise type_error(
        "indices must be integers, not '\{other.type_name()}'",
        span,
      )
  }
  let j = if i < 0 { i + length } else { i }
  if j < 0 || j >= length {
    raise err(
      Runtime("IndexError"),
      "index \{i} is out of range",
      span,
      label=key.label,
    )
  }
  j
}

///|
fn Ctx::define_class(
  self : Ctx,
  name : String,
  bases : Array[@ast.Expr],
  body : Array[@ast.Stmt],
  decorators : Array[@ast.Expr],
  span : @basic.Span,
) -> Unit raise PlanError {
  let ok_base = bases
    .iter()
    .all(b => b is Name(id="BaseModel" | "TypedDict", ..))
  let ok_decorator = decorators.iter().all(d => d is Name(id="dataclass", ..))
  if !ok_base || !ok_decorator {
    raise unsupported(
      "only data classes are available: `class \{name}(BaseModel):` with annotated fields",
      span,
    )
  }
  let fields = []
  for s in body {
    match s {
      AnnAssign(target=Name(id~, ..), annotation~, value=None, ..) =>
        fields.push({ name: id, type_: annotation_text(annotation), doc: "", })
      Pass(..) => ()
      ExprStmt(value=Constant(value=Str(_), ..), ..) => ()
      other =>
        raise unsupported(
          "a class body may only contain field annotations without defaults",
          stmt_span(other),
        )
    }
  }
  self.session.plan_types[name] = { name, fields, doc: "", }
}

///|
/// Renders a type annotation back to text (`list[str]`, `int | None`).
fn annotation_text(e : @ast.Expr) -> String {
  match e {
    Name(id~, ..) => id
    Constant(value=None, ..) => "None"
    Constant(value=Str(s), ..) => s
    Attribute(attr~, ..) => attr
    Subscript(value~, slice~, ..) =>
      "\{annotation_text(value)}[\{annotation_text(slice)}]"
    BinOp(left~, op=BitOr, right~, ..) =>
      "\{annotation_text(left)} | \{annotation_text(right)}"
    Tuple(elts~, ..) => elts.map(annotation_text).join(", ")
    _ => "Any"
  }
}

///|
fn stmt_span(s : @ast.Stmt) -> @basic.Span {
  match s {
    FunctionDef(span~, ..)
    | ClassDef(span~, ..)
    | Return(span~, ..)
    | Delete(span~, ..)
    | Assign(span~, ..)
    | AugAssign(span~, ..)
    | AnnAssign(span~, ..)
    | For(span~, ..)
    | While(span~, ..)
    | If(span~, ..)
    | With(span~, ..)
    | Match(span~, ..)
    | Raise(span~, ..)
    | Try(span~, ..)
    | Assert(span~, ..)
    | Import(span~, ..)
    | ImportFrom(span~, ..)
    | Global(span~, ..)
    | Nonlocal(span~, ..)
    | ExprStmt(span~, ..)
    | Pass(span~)
    | Break(span~)
    | Continue(span~) => span
  }
}
