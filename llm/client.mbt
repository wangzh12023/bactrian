///|
/// Where and how to reach an OpenAI-compatible chat completions endpoint.
///
/// Works with DeepSeek, Qwen (DashScope compatible mode), GLM, Kimi, Baidu
/// Qianfan v2 (`https://qianfan.baidubce.com/v2`), Baidu AI Studio
/// (`https://aistudio.baidu.com/llm/lmapi/v3`) and any OpenAI-compatible
/// gateway: the client only appends `/chat/completions` to `base_url`.
pub(all) struct Endpoint {
  base_url : String
  api_key : String
  model : String
  temperature : Double
  max_tokens : Int
} derive(Debug)

///|
pub fn Endpoint::new(
  base_url : String,
  api_key : String,
  model : String,
  temperature? : Double = 0.0,
  max_tokens? : Int = 2048,
) -> Endpoint {
  let base = if base_url.has_suffix("/") {
    base_url[:base_url.length() - 1].to_owned()
  } else {
    base_url
  }
  { base_url: base, api_key, model, temperature, max_tokens, }
}

///|
/// The URL of the chat completions endpoint.
pub fn Endpoint::url(self : Endpoint) -> String {
  self.base_url + "/chat/completions"
}

///|
/// The request body for a chat completion.
pub fn Endpoint::request_body(
  self : Endpoint,
  messages : ArrayView[@agent.Message],
  json_mode? : Bool = false,
) -> Json {
  let body : Map[String, Json] = {
    "model": Json::string(self.model),
    "messages": Json::array(messages.iter().map(m => m.to_json()).collect()),
    "temperature": Json::number(self.temperature),
    "max_tokens": Json::number(self.max_tokens.to_double()),
    "stream": Json::boolean(false),
  }
  if json_mode {
    body["response_format"] = { "type": "json_object" }
  }
  Json::object(body)
}

///|
pub(all) suberror LlmError {
  /// The endpoint answered with an HTTP error.
  Http(status~ : Int, body~ : String)
  /// The response was not the expected JSON shape.
  BadResponse(String)
} derive(Debug)

///|
/// Extracts the assistant's text from a chat completions response. Thinking
/// models may return their answer after a reasoning block; only `content`
/// is used.
pub fn parse_response(text : String) -> String raise LlmError {
  let j = @json.parse(text) catch {
    _ => raise BadResponse("not JSON: " + text.view(end_offset=200).to_owned())
  }
  match j {
    { "choices": [{ "message": { "content": String(c), .. }, .. }, ..], .. } =>
      c
    { "error": { "message": String(m), .. }, .. } => raise BadResponse(m)
    _ =>
      raise BadResponse(
        "unexpected shape: " + text.view(end_offset=200).to_owned(),
      )
  }
}

///|
/// Sends one chat completion request and returns the assistant's text.
pub async fn complete(
  endpoint : Endpoint,
  messages : ArrayView[@agent.Message],
  json_mode? : Bool = false,
) -> String {
  let text = post_text(endpoint, endpoint.request_body(messages, json_mode~))
  parse_response(text)
}

///|
/// Sends an arbitrary request body to the chat completions endpoint and
/// returns the parsed JSON response (used by the tool-calling baseline).
pub async fn post_json(endpoint : Endpoint, body : Json) -> Json {
  let text = post_text(endpoint, body)
  @json.parse(text) catch {
    _ => raise BadResponse("not JSON: " + text.view(end_offset=200).to_owned())
  }
}

///|
async fn post_text(endpoint : Endpoint, body : Json) -> String {
  let headers : Map[@http.CaseInsensitiveString, String] = {
    "Content-Type": "application/json",
    "Authorization": "Bearer \{endpoint.api_key}",
  }
  // Transient gateway errors are retried a few times.
  for attempt = 0; ; attempt = attempt + 1 {
    let (resp, data) = @http.post(endpoint.url(), body.stringify(), headers~)
    let text = data.text()
    if resp.code >= 200 && resp.code < 300 {
      return text
    }
    if attempt >= 3 || !(resp.code == 429 || resp.code >= 500) {
      raise Http(status=resp.code, body=text.view(end_offset=500).to_owned())
    }
    @async.sleep(1000 * (attempt + 1))
  }
}
