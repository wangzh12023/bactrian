///|
/// Builds the messages for the quarantined LLM: the system prompt, the JSON
/// Schema of the answer (with the `have_enough_information` escape hatch),
/// and the query composed by the plan.
pub fn quarantined_messages(
  query : String,
  schema : @runtime.TypeSpec,
  json_schema : Json,
) -> Array[@agent.Message] {
  let with_flag = match json_schema {
    Object(m) => {
      let props = match m.get("properties") {
        Some(Object(p)) => p.copy()
        _ => Map([])
      }
      props["have_enough_information"] = {
        "type": "boolean",
        "description": "false if the text does not contain the requested information",
      }
      let o = m.copy()
      o["properties"] = Json::object(props)
      Json::object(o)
    }
    other => other
  }
  [
    {
      role: "system",
      content: @agent.quarantined_system_prompt +
      "\n\nJSON Schema of your answer (type `\{schema.name}`):\n" +
      with_flag.stringify(indent=2),
    },
    { role: "user", content: query, },
  ]
}

///|
/// Interprets the quarantined LLM's reply. The reply is untrusted, so it is
/// only accepted when it is a JSON object; whether it matches the schema is
/// checked again by the interpreter when the value is labelled.
pub fn parse_quarantined(reply : String) -> @runtime.QAnswer {
  let parsed = @json.parse(strip_fence(reply)) catch {
    _ => return NotEnoughInformation
  }
  match parsed {
    Object(m) => {
      if m.get("have_enough_information") is Some(False) {
        return NotEnoughInformation
      }
      let answer = m.copy()
      answer.remove("have_enough_information")
      Answer(Json::object(answer))
    }
    _ => NotEnoughInformation
  }
}

///|
/// Removes a surrounding ```json fence if the model added one.
fn strip_fence(s : String) -> String {
  let t = s.trim().to_owned()
  if !t.has_prefix("```") {
    return t
  }
  match t.find("\n") {
    Some(i) => {
      let body = t[i + 1:].to_owned()
      match body.rev_find("```") {
        Some(j) => body[:j].trim().to_owned()
        None => body.trim().to_owned()
      }
    }
    None => t
  }
}
