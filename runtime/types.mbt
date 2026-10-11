///|
/// The static types the runtime understands: enough to describe tool
/// signatures, tool results and the schemas the quarantined LLM must fill.
pub(all) enum Ty {
  TAny
  TNone
  TBool
  TInt
  TFloat
  TStr
  TList(Ty)
  TDict
  TRecord(String)
  TOptional(Ty)
} derive(Eq, Debug)

///|
/// Renders a type in Python annotation syntax (`list[Email]`, `str | None`).
pub fn Ty::render(self : Ty) -> String {
  match self {
    TAny => "Any"
    TNone => "None"
    TBool => "bool"
    TInt => "int"
    TFloat => "float"
    TStr => "str"
    TList(t) => "list[\{t.render()}]"
    TDict => "dict"
    TRecord(name) => name
    TOptional(t) => "\{t.render()} | None"
  }
}

///|
pub(all) suberror TypeSyntaxError {
  TypeSyntaxError(String)
} derive(Debug)

///|
/// Parses a type written in Python annotation syntax.
///
/// Accepted forms: `str`, `int`, `float`, `bool`, `None`, `Any`, `dict`,
/// `list[T]`, `T | None`, `Optional[T]`, and record names. `EmailStr` and
/// `datetime` are read as `str` because tools exchange them as strings.
pub fn Ty::parse(text : StringView) -> Ty raise TypeSyntaxError {
  let s = text.trim()
  if s.rev_find("|") is Some(i) {
    let left = s[:i].trim()
    let right = s[i + 1:].trim()
    match (left, right) {
      (_, "None") => return TOptional(Ty::parse(left))
      ("None", _) => return TOptional(Ty::parse(right))
      _ =>
        raise TypeSyntaxError(
          "unions other than `T | None` are not supported: \{s}",
        )
    }
  }
  if s.strip_suffix("]") is Some(head) && head.find("[") is Some(open) {
    let outer = head[:open].trim()
    let inner = head[open + 1:]
    match outer {
      "list" | "List" => return TList(Ty::parse(inner))
      "Optional" => return TOptional(Ty::parse(inner))
      "dict" | "Dict" => return TDict
      _ => raise TypeSyntaxError("unsupported generic type: \{s}")
    }
  }
  match s {
    "str" | "EmailStr" | "datetime" | "date" => TStr
    "int" => TInt
    "float" => TFloat
    "bool" => TBool
    "None" | "NoneType" => TNone
    "Any" | "object" => TAny
    "dict" | "Dict" => TDict
    "list" | "List" => TList(TAny)
    "" => raise TypeSyntaxError("empty type")
    name =>
      if name
        .iter()
        .all(c => c.is_ascii_alphabetic() || c.is_ascii_digit() || c == '_') {
        TRecord(name.to_owned())
      } else {
        raise TypeSyntaxError("not a type: \{name}")
      }
  }
}

///|
/// The JSON Schema used to ask a model for a value of this type.
pub fn Ty::to_json_schema(self : Ty, types : Map[String, TypeSpec]) -> Json {
  match self {
    TAny => {}
    TNone => { "type": "null" }
    TBool => { "type": "boolean" }
    TInt => { "type": "integer" }
    TFloat => { "type": "number" }
    TStr => { "type": "string" }
    TList(t) => { "type": "array", "items": t.to_json_schema(types) }
    TDict => { "type": "object" }
    TOptional(t) => { "anyOf": [t.to_json_schema(types), { "type": "null" }] }
    TRecord(name) =>
      match types.get(name) {
        None => { "type": "object" }
        Some(spec) => {
          let props : Map[String, Json] = Map([])
          for f in spec.fields {
            let schema = match
              (Ty::parse(f.type_) catch { _ => TAny }).to_json_schema(types) {
              Object(m) if f.doc != "" => {
                let m2 = m.copy()
                m2["description"] = Json::string(f.doc)
                Json::object(m2)
              }
              other => other
            }
            props[f.name] = schema
          }
          {
            "type": "object",
            "properties": Json::object(props),
            "required": Json::array(spec.fields.map(f => Json::string(f.name))),
          }
        }
      }
  }
}

///|
/// Labels attached to parts of a tool result, addressed by path.
///
/// Paths use `[i]` for list elements and `.name` for object fields, so the
/// sender of the third e-mail is `[2].sender` and the whole result is `""`.
pub(all) struct PathLabels {
  parties : Map[String, Array[@label.Source]]
  readers : Map[String, @label.Readers]
} derive(Debug)

///|
pub fn PathLabels::empty() -> PathLabels {
  { parties: Map([]), readers: Map([]), }
}

///|
/// Raised when a JSON value does not have the expected type.
pub(all) suberror ShapeError {
  ShapeError(String)
} derive(Debug)

///|
/// Converts JSON into a labelled value of type `ty`.
///
/// `base` is the label of the whole value; every node additionally receives
/// the sources and reader restrictions registered for its path, and keeps
/// those of its ancestors. Objects of a record type become records (with
/// attribute access); untyped objects become dicts.
pub fn json_to_item(
  j : Json,
  ty : Ty,
  base : @label.Label,
  types : Map[String, TypeSpec],
  paths? : PathLabels = PathLabels::empty(),
) -> Item raise ShapeError {
  typed_node({ paths, types, }, j, ty, base, "")
}

///|
priv struct Labeller {
  paths : PathLabels
  types : Map[String, TypeSpec]
}

///|
fn Labeller::label_at(
  self : Labeller,
  inherited : @label.Label,
  path : String,
) -> @label.Label {
  let with_parties = match self.paths.parties.get(path) {
    Some(sources) =>
      sources.fold(init=inherited, (acc, s) => {
        ..acc,
        sources: acc.sources.add(s),
      })
    None => inherited
  }
  match self.paths.readers.get(path) {
    Some(r) => with_parties.with_readers(with_parties.readers.meet(r))
    None => with_parties
  }
}

///|
fn typed_node(
  lb : Labeller,
  j : Json,
  ty : Ty,
  inherited : @label.Label,
  path : String,
) -> Item raise ShapeError {
  let lbl = lb.label_at(inherited, path)
  match (ty, j) {
    (TOptional(_), Null) | (TNone, Null) => { value: VNone, label: lbl, }
    (TOptional(t), _) => typed_node(lb, j, t, inherited, path)
    (TAny, _) => untyped_node(lb, j, lbl, path)
    (TBool, True) => { value: VBool(true), label: lbl, }
    (TBool, False) => { value: VBool(false), label: lbl, }
    (TInt, Number(n, ..)) if n == n.floor() =>
      { value: VInt(n.to_int64()), label: lbl, }
    (TFloat, Number(n, ..)) => { value: VFloat(n), label: lbl, }
    (TStr, String(s)) => { value: VStr(s), label: lbl, }
    (TList(t), Array(xs)) => {
      let items = []
      for i, x in xs {
        items.push(typed_node(lb, x, t, lbl, "\{path}[\{i}]"))
      }
      { value: VList({ items, shape: lbl, }), label: lbl, }
    }
    (TDict, Object(_)) => untyped_node(lb, j, lbl, path)
    (TRecord(name), Object(m)) => {
      let fields : Map[String, Item] = Map([])
      match lb.types.get(name) {
        Some(spec) =>
          for f in spec.fields {
            let fty = Ty::parse(f.type_) catch {
              TypeSyntaxError(msg) => raise ShapeError(msg)
            }
            let sub = "\{path}.\{f.name}"
            match m.get(f.name) {
              Some(v) => fields[f.name] = typed_node(lb, v, fty, lbl, sub)
              None =>
                match fty {
                  TOptional(_) | TAny =>
                    fields[f.name] = {
                      value: VNone,
                      label: lb.label_at(lbl, sub),
                    }
                  _ =>
                    raise ShapeError(
                      "missing field `\{f.name}` of \{name} at `\{sub}`",
                    )
                }
            }
          }
        None =>
          for k, v in m {
            let sub = "\{path}.\{k}"
            fields[k] = untyped_node(lb, v, lb.label_at(lbl, sub), sub)
          }
      }
      { value: VRecord({ type_name: name, fields, }), label: lbl, }
    }
    _ => {
      let at = if path == "" { "<root>" } else { path }
      raise ShapeError(
        "expected \{ty.render()} at `\{at}`, got \{json_kind(j)}",
      )
    }
  }
}

///|
fn untyped_node(
  lb : Labeller,
  j : Json,
  lbl : @label.Label,
  path : String,
) -> Item {
  match j {
    Null => { value: VNone, label: lbl, }
    True => { value: VBool(true), label: lbl, }
    False => { value: VBool(false), label: lbl, }
    Number(n, ..) =>
      if n == n.floor() && n.abs() < 9.0e15 {
        { value: VInt(n.to_int64()), label: lbl, }
      } else {
        { value: VFloat(n), label: lbl, }
      }
    String(s) => { value: VStr(s), label: lbl, }
    Array(xs) => {
      let items = xs.mapi((i, x) => {
        let sub = "\{path}[\{i}]"
        untyped_node(lb, x, lb.label_at(lbl, sub), sub)
      })
      { value: VList({ items, shape: lbl, }), label: lbl, }
    }
    Object(m) => {
      let entries : Map[String, (Item, Item)] = Map([])
      for k, v in m {
        let sub = "\{path}.\{k}"
        entries["s:" + k] = (
          { value: VStr(k), label: lbl, },
          untyped_node(lb, v, lb.label_at(lbl, sub), sub),
        )
      }
      { value: VDict({ entries, shape: lbl, }), label: lbl, }
    }
  }
}

///|
fn json_kind(j : Json) -> String {
  match j {
    Null => "null"
    True | False => "a boolean"
    Number(_, ..) => "a number"
    String(_) => "a string"
    Array(_) => "an array"
    Object(_) => "an object"
  }
}
