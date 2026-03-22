# Mutation Strategies Operators Configuration

```json
{
  "INT_SIZE_AMPLIFICATION": {
    "description": "For suspected integer/size-related bugs, try boundary and oversized values.",
    "operators": [
      "set_to_zero",
      "set_to_max_32bit",
      "set_to_max_16bit",
      "multiply_by_2",
      "square"
    ]
  },
  "BUFFER_OVERFLOW_PAYLOAD": {
    "description": "For suspected buffer overflows, blow up payload-like fields.",
    "operators": [
      "repeat_pattern",
      "append_AAAA_block",
      "set_length_to_large"
    ]
  },
  "ENCODING_UNICODE_EDGE": {
    "description": "For encoding issues, use malformed unicode / control chars.",
    "operators": [
      "insert_unpaired_surrogate",
      "insert_null_bytes",
      "insert_control_chars"
    ]
  }
}
```
