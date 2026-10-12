///|
test "excerpt never reads past the end or splits a character" {
  inspect(excerpt("", 200), content="")
  inspect(excerpt("502 Bad Gateway", 200), content="502 Bad Gateway")
  inspect(excerpt("abcdef", 3), content="abc")
  // "😀" is two UTF-16 code units: cutting after the first would leave half
  // a character.
  inspect(excerpt("ab😀cd", 3), content="ab")
  inspect(excerpt("ab😀cd", 4), content="ab😀")
}

///|
test "strip_fence" {
  inspect(strip_fence("  {\"a\": 1}\n"), content="{\"a\": 1}")
  inspect(strip_fence("```json\n{\"a\": 1}\n```"), content="{\"a\": 1}")
  inspect(strip_fence("```\n{\"a\": 1}\n```\n"), content="{\"a\": 1}")
  inspect(strip_fence("```JSON\n  {\"a\": 1}  \n```"), content="{\"a\": 1}")
  // No closing fence: everything after the opening line.
  inspect(strip_fence("```json\n{\"a\": 1}"), content="{\"a\": 1}")
  // A fence on a single line is left alone (and then fails to parse).
  inspect(strip_fence("```json {\"a\": 1}```"), content="```json {\"a\": 1}```")
  // Only the last closing fence ends the block.
  inspect(
    strip_fence("```json\n{\"code\": \"```\"}\n```"),
    content="{\"code\": \"```\"}",
  )
}
