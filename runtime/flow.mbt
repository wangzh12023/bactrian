///|
/// Static analysis used to make control-flow labels sound.
///
/// Labelling the values assigned inside a branch is not enough: when a branch
/// is *not* taken, the variables it would have written keep their old values,
/// and those old values now reveal the condition. After every `if` and loop
/// the interpreter therefore joins the condition's label into every variable
/// the construct *may* write, whether or not it actually ran (hybrid
/// information-flow control).

///|
/// Methods that mutate their receiver.
let mutating_methods : Array[String] = [
  "append", "extend", "insert", "pop", "remove", "clear", "sort", "reverse", "update",
  "setdefault", "popitem",
]

///|
/// Whether calling `name` on a value of this kind mutates the receiver. Used
/// to forbid side effects inside a lambda body, where the receiver may have
/// been passed in as an argument (so the syntactic purity scan cannot see it).
fn is_mutating_method(recv : Value, name : String) -> Bool {
  match recv {
    VList(_) | VDict(_) => mutating_methods.contains(name)
    _ => false
  }
}

///|
/// Adds to `out` every variable name that `stmts` may bind or mutate.
fn may_write(stmts : ArrayView[@ast.Stmt], out : Array[String]) -> Unit {
  for s in stmts {
    match s {
      Assign(targets~, value~, ..) => {
        for t in targets {
          target_roots(t, out)
        }
        expr_writes(value, out)
      }
      AugAssign(target~, value~, ..) => {
        target_roots(target, out)
        expr_writes(value, out)
      }
      AnnAssign(target~, value~, ..) => {
        target_roots(target, out)
        if value is Some(v) {
          expr_writes(v, out)
        }
      }
      For(target~, iter~, body~, or_else~, ..) => {
        target_roots(target, out)
        expr_writes(iter, out)
        may_write(body, out)
        may_write(or_else, out)
      }
      While(cond~, body~, or_else~, ..) => {
        expr_writes(cond, out)
        may_write(body, out)
        may_write(or_else, out)
      }
      If(cond~, body~, or_else~, ..) => {
        expr_writes(cond, out)
        may_write(body, out)
        may_write(or_else, out)
      }
      ExprStmt(value~, ..) => expr_writes(value, out)
      Assert(cond~, ..) => expr_writes(cond, out)
      _ => ()
    }
  }
}

///|
/// `true` when `stmts` contain a `break` or `continue` that belongs to the
/// enclosing loop (not to a nested one).
fn may_exit_loop(stmts : ArrayView[@ast.Stmt]) -> Bool {
  stmts
  .iter()
  .any(s => {
    match s {
      Break(..) | Continue(..) => true
      If(body~, or_else~, ..) => may_exit_loop(body) || may_exit_loop(or_else)
      _ => false
    }
  })
}

///|
/// The variables whose binding or contents an assignment target changes.
fn target_roots(t : @ast.Expr, out : Array[String]) -> Unit {
  match t {
    Name(id~, ..) => push_unique(out, id)
    Tuple(elts~, ..) | List(elts~, ..) =>
      for e in elts {
        target_roots(e, out)
      }
    Subscript(value~, slice~, ..) => {
      target_roots(value, out)
      expr_writes(slice, out)
    }
    Attribute(value~, ..) | Starred(value~, ..) => target_roots(value, out)
    other => expr_writes(other, out)
  }
}

///|
/// Writes hidden inside an expression: mutating method calls and walrus
/// assignments.
fn expr_writes(e : @ast.Expr, out : Array[String]) -> Unit {
  match e {
    Call(func=Attribute(value~, attr~, ..), ..) if mutating_methods.contains(
        attr,
      ) => target_roots(value, out)
    NamedExpr(target~, ..) => target_roots(target, out)
    _ => ()
  }
  each_child(e, c => expr_writes(c, out))
}

///|
fn push_unique(out : Array[String], name : String) -> Unit {
  if !out.contains(name) {
    out.push(name)
  }
}

///|
/// Calls `f` on every direct sub-expression of `e`.
fn each_child(e : @ast.Expr, f : (@ast.Expr) -> Unit) -> Unit {
  fn comps(gs : Array[@ast.Comprehension]) {
    for g in gs {
      f(g.target)
      f(g.iter)
      for c in g.ifs {
        f(c)
      }
    }
  }

  match e {
    BoolOp(values~, ..) => values.each(f)
    NamedExpr(target~, value~, ..) => {
      f(target)
      f(value)
    }
    BinOp(left~, right~, ..) => {
      f(left)
      f(right)
    }
    UnaryOp(operand~, ..) => f(operand)
    Lambda(body~, ..) => f(body)
    IfExp(cond~, body~, or_else~, ..) => {
      f(cond)
      f(body)
      f(or_else)
    }
    Dict(keys~, values~, ..) => {
      for k in keys {
        if k is Some(k) {
          f(k)
        }
      }
      values.each(f)
    }
    Set(elts~, ..) | List(elts~, ..) | Tuple(elts~, ..) => elts.each(f)
    ListComp(elt~, generators~, ..)
    | SetComp(elt~, generators~, ..)
    | GeneratorExp(elt~, generators~, ..) => {
      f(elt)
      comps(generators)
    }
    DictComp(key~, value~, generators~, ..) => {
      f(key)
      f(value)
      comps(generators)
    }
    Await(value~, ..) | YieldFrom(value~, ..) => f(value)
    Yield(value~, ..) => if value is Some(v) { f(v) }
    Compare(left~, comparators~, ..) => {
      f(left)
      comparators.each(f)
    }
    Call(func~, args~, keywords~, ..) => {
      f(func)
      args.each(f)
      for k in keywords {
        f(k.value)
      }
    }
    JoinedStr(parts~, ..) =>
      for p in parts {
        if p is Hole(value~, ..) {
          f(value)
        }
      }
    Attribute(value~, ..) | Starred(value~, ..) => f(value)
    Subscript(value~, slice~, ..) => {
      f(value)
      f(slice)
    }
    Slice(lower~, upper~, step~, ..) => {
      if lower is Some(x) {
        f(x)
      }
      if upper is Some(x) {
        f(x)
      }
      if step is Some(x) {
        f(x)
      }
    }
    Constant(..) | Name(..) => ()
  }
}
