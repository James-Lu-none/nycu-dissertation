# Input-Output Scheme v2

## LLM input scheme

```json
{
  "seed": {
    "width": 256,
    "height": 256,
    "type": 1,
    "length": 20
  },
  "constraints": [
    {
      "id": "C1",
      "description": "length < width * height must be satisfied",
      "status": "unsatisfied"
    },
    {
      "id": "C2",
      "description": "type == 2 must be satisfied",
      "status": "unsatisfied"
    }
  ],
  "code_context": "if (type == 2 && length < width * height) { memcpy(...); }...",
  "sanitizer_report": null
}

```

## LLM output scheme

```json
{
  "predicted_cwe": ["CWE-119", "CWE-190"],
  "reasoning": "The crash is a heap-buffer-overflow in process_pixels influenced by width*height, typical of integer overflow leading to OOB write.",
  "chosen_mutation_strategy": "INT_SIZE_AMPLIFICATION",
  "mutations": [
    {
      "field": "width",
      "new_values": [65535, 10000]
    },
    {
      "field": "height",
      "new_values": [65535, 10000]
    }
  ],
  "new_seeds": [
    {
      "width": 65535,
      "height": 65535,
      "color_type": 2,
      "bit_depth": 8
    },
    {
      "width": 10000,
      "height": 10000,
      "color_type": 2,
      "bit_depth": 8
    }
  ]
}
```
