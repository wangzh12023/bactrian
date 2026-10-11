///|
using @label {type Label}

///|
/// A labelled runtime value.
///
/// Every variable binding, list element, dict entry and record field is an
/// `Item`, so the label travels with the value through every operation. For a
/// container, `label` is the label of the *reference* (how the program got
/// hold of it); the container's own `shape` label (what decided its length,
/// keys and order) lives inside the container object because it is shared by
/// every alias.
pub(all) struct Item {
  value : Value
  label : Label
}

///|
pub(all) enum Value {
  VNone
  VBool(Bool)
  VInt(Int64)
  VFloat(Double)
  VStr(String)
  VList(ListObj)
  VTuple(Array[Item])
  VDict(DictObj)
  VRecord(RecordObj)
  VFunc(Func)
  VClass(ClassRef)
}

///|
/// A mutable list. `shape` records everything that influenced the length and
/// the order of the elements.
pub(all) struct ListObj {
  items : Array[Item]
  mut shape : Label
}

///|
/// A mutable dict keyed by the canonical form of the key (see `key_of`).
pub(all) struct DictObj {
  entries : Map[String, (Item, Item)]
  mut shape : Label
}

///|
/// An immutable typed object: a tool result or a value produced by the
/// quarantined LLM according to a schema.
pub(all) struct RecordObj {
  type_name : String
  fields : Map[String, Item]
}

///|
pub(all) enum Func {
  Builtin(String)
  Tool(String)
  Method(Item, String)
  Lambda(LambdaObj)
}

///|
pub(all) struct LambdaObj {
  params : Array[String]
  body : @ast.Expr
  scopes : Array[Map[String, Item]]
}

///|
pub(all) enum ClassRef {
  /// `str`, `int`, `float`, `bool`, `list`, `dict`, `tuple`
  BuiltinType(String)
  /// A record type: declared by a tool signature or by the plan
  /// (`class Bill(BaseModel): ...`).
  RecordType(String)
  /// `ValueError` and friends; calling one builds an exception value.
  ErrorType(String)
}

///|
pub fn Item::new(value : Value, label : Label) -> Item {
  { value, label, }
}

///|
pub fn Item::with_label(self : Item, label : Label) -> Item {
  { ..self, label, }
}

///|
/// Adds `extra` to the label of the reference (not to the elements).
pub fn Item::taint(self : Item, extra : Label) -> Item {
  { ..self, label: self.label.join(extra), }
}

///|
/// The label that decides the observable *structure* of the value: for a
/// scalar its label, for a container the reference label joined with the
/// container's shape. Truthiness, `len` and iteration depend on this label
/// only, not on the elements.
pub fn Item::top(self : Item) -> Label {
  match self.value {
    VList(l) => self.label.join(l.shape)
    VDict(d) => self.label.join(d.shape)
    _ => self.label
  }
}

///|
/// The label of everything reachable from this value. This is what a policy
/// sees for a tool argument.
pub fn Item::deep(self : Item) -> Label {
  let visited : Array[ListObj] = []
  let visited_dicts : Array[DictObj] = []
  fn go(it : Item) -> Label {
    match it.value {
      VList(l) => {
        if visited.iter().any(v => physical_equal(v, l)) {
          return it.label
        }
        visited.push(l)
        l.items
        .iter()
        .fold(init=it.label.join(l.shape), (acc, x) => acc.join(go(x)))
      }
      VDict(d) => {
        if visited_dicts.iter().any(v => physical_equal(v, d)) {
          return it.label
        }
        visited_dicts.push(d)
        d.entries
        .values()
        .fold(init=it.label.join(d.shape), (acc, kv) => {
          acc.join(go(kv.0)).join(go(kv.1))
        })
      }
      VTuple(xs) => xs.iter().fold(init=it.label, (acc, x) => acc.join(go(x)))
      VRecord(r) =>
        r.fields.values().fold(init=it.label, (acc, x) => acc.join(go(x)))
      VFunc(Method(recv, _)) => it.label.join(go(recv))
      _ => it.label
    }
  }

  go(self)
}

///|
pub fn Value::type_name(self : Value) -> String {
  match self {
    VNone => "NoneType"
    VBool(_) => "bool"
    VInt(_) => "int"
    VFloat(_) => "float"
    VStr(_) => "str"
    VList(_) => "list"
    VTuple(_) => "tuple"
    VDict(_) => "dict"
    VRecord(r) => r.type_name
    VFunc(Lambda(_)) => "function"
    VFunc(Method(_, _)) => "method"
    VFunc(_) => "builtin_function_or_method"
    VClass(_) => "type"
  }
}

///|
/// Python truthiness.
pub fn Value::truthy(self : Value) -> Bool {
  match self {
    VNone => false
    VBool(b) => b
    VInt(i) => i != 0L
    VFloat(f) => f != 0.0
    VStr(s) => s != ""
    VList(l) => !l.items.is_empty()
    VTuple(xs) => !xs.is_empty()
    VDict(d) => !d.entries.is_empty()
    _ => true
  }
}

///|
/// `str(x)` in Python.
pub fn Value::to_str(self : Value) -> String {
  match self {
    VStr(s) => s
    _ => self.repr()
  }
}

///|
/// `repr(x)` in Python.
pub fn Value::repr(self : Value) -> String {
  match self {
    VNone => "None"
    VBool(true) => "True"
    VBool(false) => "False"
    VInt(i) => i.to_string()
    VFloat(f) => @basic.py_float_repr(f)
    VStr(s) => @basic.py_repr(s)
    VList(l) => "[" + l.items.map(x => x.value.repr()).join(", ") + "]"
    VTuple([x]) => "(" + x.value.repr() + ",)"
    VTuple(xs) => "(" + xs.map(x => x.value.repr()).join(", ") + ")"
    VDict(d) =>
      "{" +
      d.entries
      .values()
      .map(kv => kv.0.value.repr() + ": " + kv.1.value.repr())
      .collect()
      .join(", ") +
      "}"
    VRecord(r) =>
      r.type_name +
      "(" +
      r.fields
      .iter()
      .map(kv => kv.0 + "=" + kv.1.value.repr())
      .collect()
      .join(", ") +
      ")"
    VFunc(Builtin(name)) | VFunc(Tool(name)) => "<function \{name}>"
    VFunc(Method(recv, name)) => "<method \{recv.value.type_name()}.\{name}>"
    VFunc(Lambda(_)) => "<lambda>"
    VClass(BuiltinType(name))
    | VClass(RecordType(name))
    | VClass(ErrorType(name)) => "<class '\{name}'>"
  }
}

///|
/// The canonical dictionary key of a hashable value, `None` when the value is
/// unhashable (lists, dicts, records).
pub fn key_of(v : Value) -> String? {
  match v {
    VNone => Some("n")
    VBool(b) => Some(if b { "i:1" } else { "i:0" })
    VInt(i) => Some("i:" + i.to_string())
    VFloat(f) =>
      if f == f.floor() && f.abs() < 9.0e15 {
        Some("i:" + f.to_int64().to_string())
      } else {
        Some("f:" + @basic.py_float_repr(f))
      }
    VStr(s) => Some("s:" + s)
    VTuple(xs) => {
      let parts = []
      for x in xs {
        match key_of(x.value) {
          Some(k) => parts.push(k)
          None => return None
        }
      }
      Some("t:(" + parts.join(",") + ")")
    }
    _ => None
  }
}

///|
/// Structural equality following Python (`1 == 1.0`, `True == 1`).
pub fn values_equal(a : Value, b : Value) -> Bool {
  match (a, b) {
    (VNone, VNone) => true
    (VStr(x), VStr(y)) => x == y
    (VList(x), VList(y)) => items_equal(x.items, y.items)
    (VTuple(x), VTuple(y)) => items_equal(x, y)
    (VDict(x), VDict(y)) =>
      x.entries.length() == y.entries.length() &&
      x.entries
      .iter()
      .all(kv => {
        match y.entries.get(kv.0) {
          Some((_, v)) => values_equal(kv.1.1.value, v.value)
          None => false
        }
      })
    (VRecord(x), VRecord(y)) =>
      x.type_name == y.type_name &&
      x.fields.length() == y.fields.length() &&
      x.fields
      .iter()
      .all(kv => {
        match y.fields.get(kv.0) {
          Some(v) => values_equal(kv.1.value, v.value)
          None => false
        }
      })
    (VClass(x), VClass(y)) => x == y
    _ =>
      match (as_number(a), as_number(b)) {
        (Some(x), Some(y)) => x == y
        _ => false
      }
  }
}

///|
fn items_equal(xs : Array[Item], ys : Array[Item]) -> Bool {
  xs.length() == ys.length() &&
  xs.iter().zip(ys.iter()).all(p => values_equal(p.0.value, p.1.value))
}

///|
pub impl Eq for ClassRef with fn equal(a, b) {
  match (a, b) {
    (BuiltinType(x), BuiltinType(y)) => x == y
    (RecordType(x), RecordType(y)) => x == y
    (ErrorType(x), ErrorType(y)) => x == y
    _ => false
  }
}

///|
/// Numeric view of a value: bools, ints and floats.
pub fn as_number(v : Value) -> Double? {
  match v {
    VBool(b) => Some(if b { 1.0 } else { 0.0 })
    VInt(i) => Some(i.to_double())
    VFloat(f) => Some(f)
    _ => None
  }
}

///|
/// Python ordering; `None` when the two values are not comparable.
pub fn values_compare(a : Value, b : Value) -> Int? {
  match (a, b) {
    (VStr(x), VStr(y)) => Some(x.compare(y))
    (VList(x), VList(y)) => items_compare(x.items, y.items)
    (VTuple(x), VTuple(y)) => items_compare(x, y)
    (VInt(x), VInt(y)) => Some(x.compare(y))
    _ =>
      match (as_number(a), as_number(b)) {
        (Some(x), Some(y)) => Some(x.compare(y))
        _ => None
      }
  }
}

///|
fn items_compare(xs : Array[Item], ys : Array[Item]) -> Int? {
  let n = if xs.length() < ys.length() { xs.length() } else { ys.length() }
  for i in 0..<n {
    match values_compare(xs[i].value, ys[i].value) {
      Some(0) => continue
      other => return other
    }
  }
  Some(xs.length().compare(ys.length()))
}

///|
/// Converts a value to JSON for tool arguments, policies and the quarantined
/// LLM. Functions and classes have no JSON form and become their `repr`.
pub fn Value::to_json(self : Value) -> Json {
  match self {
    VNone => Json::null()
    VBool(b) => Json::boolean(b)
    VInt(i) => Json::number(i.to_double())
    VFloat(f) => Json::number(f)
    VStr(s) => Json::string(s)
    VList(l) => Json::array(l.items.map(x => x.value.to_json()))
    VTuple(xs) => Json::array(xs.map(x => x.value.to_json()))
    VDict(d) => {
      let m : Map[String, Json] = Map([])
      for kv in d.entries.values() {
        m[kv.0.value.to_str()] = kv.1.value.to_json()
      }
      Json::object(m)
    }
    VRecord(r) => {
      let m : Map[String, Json] = Map([])
      for k, v in r.fields {
        m[k] = v.value.to_json()
      }
      Json::object(m)
    }
    VFunc(_) | VClass(_) => Json::string(self.repr())
  }
}

///|
/// Builds a list item whose shape and elements share `label`.
pub fn list_item(items : Array[Item], label : Label, shape? : Label) -> Item {
  let shape = shape.unwrap_or(label)
  { value: VList({ items, shape, }), label, }
}

///|
pub fn str_item(s : String, label : Label) -> Item {
  { value: VStr(s), label, }
}

///|
pub fn none_item(label : Label) -> Item {
  { value: VNone, label, }
}
