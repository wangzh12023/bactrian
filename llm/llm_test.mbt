///|
/// The quarantined model's reply as text: `Answer <json>` or
/// `NotEnoughInformation`.
fn show(a : @runtime.QAnswer) -> String {
  match a {
    Answer(j) => "Answer " + j.stringify()
    NotEnoughInformation => "NotEnoughInformation"
  }
}

///|
test "parse_quarantined: a plain JSON answer, without the flag" {
  inspect(
    show(
      @llm.parse_quarantined(
        "{\"iban\": \"UK12345678901234567890\", \"amount\": 98.7, \"have_enough_information\": true}",
      ),
    ),
    content=(
      #|Answer {"iban":"UK12345678901234567890","amount":98.7}
    ),
  )
  // The flag is optional, and surrounding whitespace is ignored.
  inspect(
    show(@llm.parse_quarantined("\n  {\"city\": \"Paris\"}  \n")),
    content=(
      #|Answer {"city":"Paris"}
    ),
  )
}

///|
test "parse_quarantined: a fenced answer" {
  inspect(
    show(
      @llm.parse_quarantined(
        (
          #|```json
          #|{"increase": 100.0}
          #|```
        ),
      ),
    ),
    content=(
      #|Answer {"increase":100}
    ),
  )
  inspect(
    show(
      @llm.parse_quarantined(
        (
          #|```
          #|{"street": "Dalton Street 123"}
          #|```
        ),
      ),
    ),
    content=(
      #|Answer {"street":"Dalton Street 123"}
    ),
  )
  // A missing closing fence is tolerated.
  inspect(
    show(@llm.parse_quarantined("```json\n{\"a\": 1}")),
    content=(
      #|Answer {"a":1}
    ),
  )
}

///|
test "parse_quarantined: have_enough_information false" {
  inspect(
    show(
      @llm.parse_quarantined(
        "{\"have_enough_information\": false, \"iban\": \"dummy\"}",
      ),
    ),
    content="NotEnoughInformation",
  )
  inspect(
    show(
      @llm.parse_quarantined(
        "```json\n{\"have_enough_information\": false}\n```",
      ),
    ),
    content="NotEnoughInformation",
  )
}

///|
test "parse_quarantined: anything but a JSON object is not an answer" {
  // The reply is untrusted: a malformed reply never becomes data.
  for
    reply in [
      "{\"iban\": ", "", "Sure! The IBAN is UK12345678901234567890.", "Here you go: {\"iban\": \"X\"}",
      "[\"UK12345678901234567890\"]", "\"UK12345678901234567890\"", "42", "null",
      "```json {\"a\": 1}```",
    ] {
    inspect(show(@llm.parse_quarantined(reply)), content="NotEnoughInformation")
  }
}

///|
/// What `parse_response` returns or raises, as text.
fn response(text : String) -> String {
  try @llm.parse_response(text) catch {
    BadResponse(m) => "BadResponse: " + m
    Http(status~, body~) => "Http \{status}: \{body}"
  } noraise {
    content => "content: " + content
  }
}

///|
test "parse_response: the assistant's content" {
  inspect(
    response(
      "{\"id\": \"c1\", \"choices\": [{\"index\": 0, \"message\": {\"role\": \"assistant\", \"content\": \"print(1)\"}, \"finish_reason\": \"stop\"}]}",
    ),
    content="content: print(1)",
  )
  // Thinking models put their reasoning beside the answer: only the content
  // is used.
  inspect(
    response(
      "{\"choices\": [{\"message\": {\"reasoning_content\": \"let me think\", \"content\": \"answer\"}}]}",
    ),
    content="content: answer",
  )
}

///|
test "parse_response: an error body" {
  inspect(
    response(
      "{\"error\": {\"message\": \"Incorrect API key provided\", \"type\": \"invalid_request_error\", \"code\": \"invalid_api_key\"}}",
    ),
    content="BadResponse: Incorrect API key provided",
  )
}

///|
test "parse_response: malformed bodies" {
  inspect(
    response("<html><body>502 Bad Gateway</body></html>"),
    content="BadResponse: not JSON: <html><body>502 Bad Gateway</body></html>",
  )
  inspect(
    response("{\"choices\": []}"),
    content="BadResponse: unexpected shape: {\"choices\": []}",
  )
  // A reply without text content (e.g. only tool calls).
  inspect(
    response("{\"choices\": [{\"message\": {\"content\": null}}]}"),
    content="BadResponse: unexpected shape: {\"choices\": [{\"message\": {\"content\": null}}]}",
  )
  // Long bodies are cut to 200 characters in the message.
  let long = "x".repeat(1000)
  inspect(
    response(long).length(),
    content="\{"BadResponse: not JSON: ".length() + 200}",
  )
}

///|
test "endpoint URL and request body" {
  let e = @llm.Endpoint::new("https://api.example.com/v1/", "sk-test", "m1")
  inspect(e.url(), content="https://api.example.com/v1/chat/completions")
  let messages : Array[@agent.Message] = [{ role: "user", content: "hi", }]
  inspect(
    e.request_body(messages).stringify(),
    content=(
      #|{"model":"m1","messages":[{"role":"user","content":"hi"}],"temperature":0,"max_tokens":2048,"stream":false}
    ),
  )
  inspect(
    e.request_body(messages, json_mode=true).stringify(),
    content=(
      #|{"model":"m1","messages":[{"role":"user","content":"hi"}],"temperature":0,"max_tokens":2048,"stream":false,"response_format":{"type":"json_object"}}
    ),
  )
}

///|
test "quarantined_messages adds the escape hatch to the schema" {
  let schema : @runtime.TypeSpec = {
    name: "Bill",
    fields: [{ name: "iban", type_: "str", doc: "", }],
    doc: "",
  }
  let json_schema : Json = {
    "type": "object",
    "properties": { "iban": { "type": "string" } },
    "required": ["iban"],
  }
  let ms = @llm.quarantined_messages("Who should be paid?", schema, json_schema)
  inspect(ms.map(m => m.role).join(","), content="system,user")
  inspect(ms[1].content, content="Who should be paid?")
  assert_true(ms[0].content.has_prefix(@agent.quarantined_system_prompt))
  assert_true(ms[0].content.contains("type `Bill`"))
  assert_true(ms[0].content.contains("\"have_enough_information\""))
  assert_true(ms[0].content.contains("\"iban\""))
  // The caller's schema is not modified.
  inspect(
    json_schema.stringify(),
    content=(
      #|{"type":"object","properties":{"iban":{"type":"string"}},"required":["iban"]}
    ),
  )
}
