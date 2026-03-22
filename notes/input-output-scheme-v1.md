# Input-Output Scheme v1 

## LLM Input Schema

context: 與目前 fuzz iteration 相關的程式碼資訊
seed: 目前 fuzz 輸入（raw 與 decoded）
path_constraints: 哪些 branch conditions 被卡住（LLM 需理解）
sanitizer_feedback: 若有 crash，包含 ASan/UBSan/TSan 報告
fuzzing_feedback: fuzzing stagnation 訊息
task: 讓模型知道它是在「做 mutation proposal」
constraints: 控制模型 output 格式、長度

```json
{
  "context": {
    "target_function": "parse_header",
    "code_snippet": "if (type == 2 && length < width * height) { memcpy(buf, data, length); }",
    "source_language": "C"
  },

  "seed": {
    "format": "decoded",
    "raw_input_hex": "89504E470D0A1A0A0000000D49484452...",
    "decoded_fields": {
      "length": 5000,
      "type": 1,
      "width": 200,
      "height": 300,
      "flags": 0
    }
  },

  "path_constraints": [
    {
      "id": "C1",
      "expr": "length < width *height",
      "status": "unsatisfied",
      "analysis_hint": "length=5000, width*height=60000"
    },
    {
      "id": "C2",
      "expr": "type == 2",
      "status": "unsatisfied",
      "analysis_hint": "type=1"
    }
  ],

  "sanitizer_feedback": {
    "asan_report": null,
    "ubsan_report": null,
    "tsan_report": null
  },

  "fuzzing_feedback": {
    "last_coverage_delta": 0,
    "iterations_without_progress": 120
  },

  "task": "propose_mutation",
  "constraints": {
    "output_format": "JSON",
    "max_mutations": 5
  }
}
```

## LLM Output Schema
analysis: 模型對目前 path constraints 的分析
mutation_plan: 模型建議的變異計畫
new_seeds: 模型產生的新 seed（decoded 格式）
format_notes: 任何關於 seed re-encoding 的注意事項

```json
{
  "analysis": {
    "blocking_constraints": [
      {
        "id": "C1",
        "reason": "length=5000 violates length < width * height (60000)."
      },
      {
        "id": "C2",
        "reason": "type must equal 2 to reach vulnerable branch."
      }
    ],
    "predicted_cwe": [
      {
        "cwe_id": "CWE-190",
        "justification": "Condition involves multiplication and comparison with user-controlled values."
      },
      {
        "cwe_id": "CWE-119",
        "justification": "Potential buffer write dependent on 'length'."
      }
    ]
  },

  "mutation_plan": [
    {
      "field": "type",
      "action": "set",
      "reason": "Needed to satisfy C2.",
      "candidate_values": [2]
    },
    {
      "field": "length",
      "action": "set",
      "reason": "Allow exploration of integer overflow boundary.",
      "candidate_values": [1, 256, 2147483647]
    }
  ],

  "new_seeds": [
    {
      "decoded_fields": {
        "length": 256,
        "type": 2,
        "width": 200,
        "height": 300,
        "flags": 0
      }
    }
  ],

  "format_notes": "Seeds must be re-encoded into binary using the field spec before fuzzing."
}
```

















```bash
┌────────────────────────────────────────────────────────────────┐
│                          1. Fuzzer Engine                      │
│                 (AFL++, libFuzzer, custom fuzz loop)           │
│                                                                │
│   • Executes target program                                    │
│   • Tracks coverage & stagnation                               │
│   • Sends seed for deeper exploration                          │
└───────────────┬────────────────────────────────────────────────┘
                │
                ▼
┌────────────────────────────────────────────────────────────────┐
│ 2. Instrumented Program + Sanitizers                           │
│    (ASan / UBSan / TSan)                                       │
│                                                                │
│   • Detects memory errors                                      │
│   • Produces crash reports                                     │
│   • Provides stack traces, OOB info, UB info                   │
└───────────────┬────────────────────────────────────────────────┘
                │ sanitizer feedback (optional)
                ▼
┌────────────────────────────────────────────────────────────────┐
│ 3. Path Constraint Extractor                                   │
│    (Taint + symbolic approximation)                            │
│                                                                │
│   • Extracts branch conditions                                 │
│   • Determines which constraints are unsatisfied               │
│   • Identifies current execution path                          │
│   • Converts constraints → HUMAN-READABLE JSON                 │
└───────────────┬────────────────────────────────────────────────┘
                │ JSON bundle: {seed, constraints, trace, code}
                ▼
┌────────────────────────────────────────────────────────────────┐
│ 4. LLM Mutation Engine                                         │
│    (Your core research contribution)                           │
│                                                                │
│   Input JSON:                                                  │
│     • decoded seed fields                                      │
│     • blocking constraints                                     │
│     • code snippet (optional)                                  │
│     • sanitizer reports                                        │
│     • fuzzing stagnation info                                  │
│                                                                │
│   LLM Tasks:                                                   │
│     • Interpret constraints                                    │
│     • Predict vulnerability semantics (CWE)                    │
│     • Select mutation strategies                               │
│     • Generate new seeds (JSON)                                │
└───────────────┬────────────────────────────────────────────────┘
                │ proposed new seed(s)
                ▼
┌────────────────────────────────────────────────────────────────┐
│ 5. Seed Re-encoder                                             │
│                                                                │
│   • Converts LLM JSON seeds back into binary / JSON input      │
│   • Validates structure                                        │
│   • Sends new seed to fuzzer                                   │
└───────────────┬────────────────────────────────────────────────┘
                │
                ▼
┌────────────────────────────────────────────────────────────────┐
│ 6. Feedback Loop Controller                                    │
│                                                                │
│   • Measures coverage impact                                   │
│   • Measures crash discovery                                   │
│   • Stores (input → LLM output → result) triples               │
│   • Feeds successful mutations back into history / buffer      │
│   • Optional: trains/fine-tunes model over time                │
└────────────────────────────────────────────────────────────────┘
```