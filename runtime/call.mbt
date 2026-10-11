///|
/// Evaluated call arguments.
priv struct Args {
  pos : Array[Item]
  kw : Array[(String, Item)]
}

///|
fn Args::kwarg(self : Args, name : String) -> Item? {
  for p in self.kw {
    if p.0 == name {
      return Some(p.1)
    }
  }
  None
}

///|
fn Ctx::eval_args(
  self : Ctx,
  args : Array[@ast.Expr],
  keywords : Array[@ast.Keyword],
  span : @basic.Span,
) -> Args raise PlanError {
  // `f(*xs)`: which argument lands in which position depends on the shape of
  // `xs`, so every positional argument carries it.
  let (raw, spread) = self.eval_elements(args, span)
  let pos = raw.map(a => a.taint(spread))
  let kw = []
  for k in keywords {
    match k.arg {
      Some(name) => kw.push((name, self.eval(k.value)))
      None =>
        match self.eval(k.value) {
          { value: VDict(d), label, } =>
            for kv in d.entries.values() {
              match kv.0.value {
                VStr(name) =>
                  kw.push((name, kv.1.taint(label.join(kv.0.label))))
                _ => raise type_error("keywords must be strings", span)
              }
            }
          _ => raise type_error("argument after ** must be a mapping", span)
        }
    }
  }
  { pos, kw, }
}

///|
fn Ctx::call(
  self : Ctx,
  func : @ast.Expr,
  args : Array[@ast.Expr],
  keywords : Array[@ast.Keyword],
  span : @basic.Span,
) -> Item raise PlanError {
  let f = self.eval(func)
  let a = self.eval_args(args, keywords, span)
  self.apply(f, a, span)
}

///|
fn Ctx::apply(
  self : Ctx,
  f : Item,
  a : Args,
  span : @basic.Span,
) -> Item raise PlanError {
  match f.value {
    VFunc(Tool(name)) => self.call_tool(name, a, span)
    VFunc(Builtin("query_ai_assistant")) => self.query_quarantined(a, span)
    VFunc(Builtin(name)) => self.call_builtin(name, a, span)
    VFunc(Method(recv, name)) =>
      self.call_method(recv, name, a, span).taint(f.label)
    VFunc(Lambda(fun)) => {
      if fun.params.length() != a.pos.length() || !a.kw.is_empty() {
        raise type_error(
          "the lambda takes \{fun.params.length()} positional arguments but \{a.pos.length()} were given",
          span,
        )
      }
      let scope : Map[String, Item] = Map([])
      for i, p in fun.params {
        scope[p] = a.pos[i]
      }
      let ctx = { ..self, scopes: [..fun.scopes, scope], }
      ctx.eval(fun.body).taint(f.label)
    }
    VClass(BuiltinType(name)) => self.call_builtin(name, a, span)
    VClass(ErrorType(name)) => {
      let msg = match a.pos {
        [] => str_item("", Label::plan())
        [x, ..] => x
      }
      let fields : Map[String, Item] = Map([("args", msg)])
      { value: VRecord({ type_name: name, fields, }), label: msg.deep(), }
    }
    VClass(RecordType(name)) => self.construct(name, a, span)
    other =>
      raise type_error("'\{other.type_name()}' object is not callable", span)
  }
}

///|
fn Ctx::type_spec(self : Ctx, name : String) -> TypeSpec? {
  match self.session.plan_types.get(name) {
    Some(t) => Some(t)
    None => self.world.types.get(name)
  }
}

///|
fn Ctx::all_types(self : Ctx) -> Map[String, TypeSpec] {
  let m = self.world.types.copy()
  for k, v in self.session.plan_types {
    m[k] = v
  }
  m
}

///|
/// `Bill(amount=1.0, iban="...")`: builds a record from keyword arguments.
fn Ctx::construct(
  self : Ctx,
  name : String,
  a : Args,
  span : @basic.Span,
) -> Item raise PlanError {
  let spec = match self.type_spec(name) {
    Some(s) => s
    None => raise err(Runtime("NameError"), "unknown type '\{name}'", span)
  }
  if !a.pos.is_empty() {
    raise type_error("\{name}(...) takes keyword arguments only", span)
  }
  let fields : Map[String, Item] = Map([])
  for f in spec.fields {
    match a.kwarg(f.name) {
      Some(v) => fields[f.name] = v
      None =>
        raise type_error("\{name}(...) is missing the field '\{f.name}'", span)
    }
  }
  for p in a.kw {
    if !fields.contains(p.0) {
      raise type_error("\{name}(...) has no field '\{p.0}'", span)
    }
  }
  { value: VRecord({ type_name: name, fields, }), label: Label::plan(), }
}

///|
/// Performs a tool call: converts the arguments to JSON, asks the policy,
/// possibly asks the user, and only then asks the host.
fn Ctx::call_tool(
  self : Ctx,
  name : String,
  a : Args,
  span : @basic.Span,
) -> Item raise PlanError {
  let spec = self.world.tools[name]
  // Bind arguments to parameter names.
  let bound : Map[String, Item] = Map([])
  for i, v in a.pos {
    match spec.params.get(i) {
      Some(p) => bound[p.name] = v
      None =>
        raise type_error(
          "\{name}() takes \{spec.params.length()} arguments but \{a.pos.length()} were given",
          span,
        )
    }
  }
  for p in a.kw {
    if !spec.params.iter().any(q => q.name == p.0) {
      raise type_error(
        "\{name}() got an unexpected keyword argument '\{p.0}'",
        span,
      )
    }
    if bound.contains(p.0) {
      raise type_error(
        "\{name}() got multiple values for argument '\{p.0}'",
        span,
      )
    }
    bound[p.0] = p.1
  }
  for p in spec.params {
    if p.required && !bound.contains(p.name) {
      raise type_error("\{name}() missing required argument '\{p.name}'", span)
    }
  }
  let args_json : Map[String, Json] = Map([])
  let arg_labels : Map[String, Label] = Map([])
  let views : Map[String, @policy.ArgView] = Map([])
  for k, v in bound {
    let j = v.value.to_json()
    let l = v.deep()
    args_json[k] = j
    arg_labels[k] = l
    views[k] = { value: j, label: l, }
  }
  self.session.calls += 1
  if self.session.calls > self.world.limits.max_calls {
    raise err(
      Budget,
      "the plan made more than \{self.world.limits.max_calls} calls",
      span,
    )
  }
  let id = self.session.next_id
  self.session.next_id += 1
  let context = self.pc
  let verdict = self.world.policy.check({ tool: name, args: views, context, })
  let record = fn(approved : Bool?, result : Json?, result_label : Label?) {
    self.session.events.push(
      ToolCall(
        id~,
        tool=name,
        args=args_json,
        arg_labels~,
        context~,
        verdict~,
        approved~,
        result~,
        result_label~,
        span~,
      ),
    )
  }
  let mut approved = false
  match verdict.decision {
    Allow => ()
    Deny(reason) => {
      record(None, None, None)
      raise err(PolicyDenied(tool=name), reason, span, label=Label::plan())
    }
    Ask(reason) => {
      let provenance = verdict.concerns.map(c => {
        (c.culprit, explain_label(c.label, self.session))
      })
      let request = { tool: name, args: args_json, reason, provenance, }
      match self.effect(Confirm(request~), span) {
        Approval(true) => approved = true
        _ => {
          record(Some(false), None, None)
          raise err(NotApproved(tool=name), reason, span, label=Label::plan())
        }
      }
    }
  }
  let result = match self.effect(CallTool(tool=name, args=args_json), span) {
    ToolOk(r) => r
    ToolError(msg) => {
      record(Some(approved), None, None)
      raise err(
        ToolFailed(tool=name),
        msg,
        span,
        label=Label::tool(name, origin=id),
      )
    }
    _ => raise err(ToolFailed(tool=name), "unexpected response", span)
  }
  let base = Label::tool(name, readers=result.readers, origin=id)
  let ty = Ty::parse(spec.returns) catch { _ => TAny }
  let item = json_to_item(
    result.value,
    ty,
    base,
    self.all_types(),
    paths=result.paths,
  ) catch {
    ShapeError(msg) => {
      record(Some(true), Some(result.value), Some(base))
      raise err(
        ToolFailed(tool=name),
        "the tool returned an unexpected value: \{msg}",
        span,
        label=base,
      )
    }
  }
  record(Some(approved), Some(result.value), Some(base))
  item
}

///|
/// `query_ai_assistant(query, Schema)`: the only way the plan can turn
/// untrusted text into structured data. The answer is labelled with everything
/// the prompt contained, so injected text can never launder itself into
/// trusted data.
fn Ctx::query_quarantined(
  self : Ctx,
  a : Args,
  span : @basic.Span,
) -> Item raise PlanError {
  let prompt = match (a.pos.get(0), a.kwarg("query")) {
    (Some(p), _) | (None, Some(p)) => p
    (None, None) => raise type_error("query_ai_assistant() needs a query", span)
  }
  let schema = match (a.pos.get(1), a.kwarg("output_schema")) {
    (Some(s), _) | (None, Some(s)) => s
    (None, None) =>
      raise type_error("query_ai_assistant() needs an output_schema", span)
  }
  let (type_name, ty) = match schema.value {
    VClass(RecordType(name)) => (name, TRecord(name))
    VClass(BuiltinType("str" | "int" | "float" | "bool" as t)) =>
      (t, Ty::parse(t) catch { _ => TStr })
    _ =>
      raise type_error(
        "output_schema must be a class declared with `class X(BaseModel)` or str/int/float/bool",
        span,
      )
  }
  let spec = match ty {
    TRecord(name) =>
      match self.type_spec(name) {
        Some(s) => s
        None => raise err(Runtime("NameError"), "unknown type '\{name}'", span)
      }
    _ =>
      {
        name: type_name,
        fields: [{ name: "value", type_: type_name, doc: "", }],
        doc: "",
      }
  }
  self.session.calls += 1
  if self.session.calls > self.world.limits.max_calls {
    raise err(
      Budget,
      "the plan made more than \{self.world.limits.max_calls} calls",
      span,
    )
  }
  let id = self.session.next_id
  self.session.next_id += 1
  let prompt_text = prompt.value.to_str()
  let prompt_label = prompt.deep().join(schema.label)
  let types = self.all_types()
  types[spec.name] = spec
  let json_schema = TRecord(spec.name).to_json_schema(types)
  let answer = match
    self.effect(
      AskQuarantined(prompt=prompt_text, schema=spec, json_schema~),
      span,
    ) {
    Quarantined(a) => a
    ToolError(msg) => {
      self.session.events.push(
        Quarantined(id~, schema=type_name, prompt_label~, answer=None, span~),
      )
      raise err(
        ToolFailed(tool="query_ai_assistant"),
        msg,
        span,
        label=prompt_label,
      )
    }
    _ =>
      raise err(
        ToolFailed(tool="query_ai_assistant"),
        "unexpected response",
        span,
      )
  }
  // The answer may depend on anything in the prompt, and on the control
  // context in which it was asked. It is also never more trusted than the
  // model itself: even from a prompt built only of trusted data, a model can
  // answer anything (it may be compromised, or simply wrong), so its output
  // always carries the untrusted source `query_ai_assistant`.
  let base = prompt_label
    .join(Label::tool("query_ai_assistant"))
    .with_origin(id)
  match answer {
    NotEnoughInformation => {
      self.session.events.push(
        Quarantined(id~, schema=type_name, prompt_label~, answer=None, span~),
      )
      raise err(
        NotEnoughInformation,
        "the assistant did not have enough information; pass it more of the data you have",
        span,
        label=base,
      )
    }
    Answer(j) => {
      self.session.events.push(
        Quarantined(id~, schema=type_name, prompt_label~, answer=Some(j), span~),
      )
      let types = self.all_types()
      match ty {
        TRecord(_) =>
          json_to_item(j, ty, base, types) catch {
            ShapeError(msg) =>
              raise err(
                ToolFailed(tool="query_ai_assistant"),
                "the assistant's answer did not match the schema: \{msg}",
                span,
                label=base,
              )
          }
        _ => {
          let inner = match j {
            Object(m) if m.get("value") is Some(v) => v
            other => other
          }
          json_to_item(inner, ty, base, types) catch {
            ShapeError(msg) =>
              raise err(
                ToolFailed(tool="query_ai_assistant"),
                "the assistant's answer did not match the schema: \{msg}",
                span,
                label=base,
              )
          }
        }
      }
    }
  }
}

///|
/// Explains a label in words: which tools and parties the data came from,
/// and who may read it.
pub fn explain_label(l : Label, session : Session) -> String {
  let parts = []
  let quarantined = l.sources.contains(Tool("query_ai_assistant")) ||
    l.origins
    .to_array()
    .any(id => {
      session.events.iter().any(e => e is Quarantined(id=i, ..) && i == id)
    })
  for s in l.sources {
    match s {
      User => parts.push("you")
      Plan => ()
      // Shown once, below.
      Tool("query_ai_assistant") => ()
      Tool(name) => {
        let calls = l.origins
          .to_array()
          .filter(id => {
            session.events
            .iter()
            .any(e => e is ToolCall(id=i, tool=t, ..) && i == id && t == name)
          })
        if calls.is_empty() {
          parts.push("the output of `\{name}`")
        } else {
          parts.push(
            "the output of `\{name}` (call #" +
            calls.map(c => c.to_string()).join(", #") +
            ")",
          )
        }
      }
      Party(who) => parts.push("content written by \{who}")
    }
  }
  if quarantined {
    parts.push("an answer of the quarantined assistant")
  }
  let from = if parts.is_empty() { "your request" } else { parts.join(", ") }
  let readers = match l.readers {
    Public => "anyone"
    Only(_) =>
      match l.readers.principals() {
        [] => "only you"
        ps => "only you and " + ps.join(", ")
      }
  }
  "comes from \{from}; may be read by \{readers}"
}
