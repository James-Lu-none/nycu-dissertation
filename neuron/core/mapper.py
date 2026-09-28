from collections import Counter
from bisect import bisect_right


def prepare_code_input(code, tokenizer, max_length=512):
    """Tokenize for the model and identify fully retained, nonempty token sets.

    Full offsets are computed on CPU only; the full sequence is never forwarded.
    Comparing offset multisets detects a cut inside a line, including duplicate
    offsets produced by byte-level tokenization of Unicode characters.
    """
    full = tokenizer(code, truncation=False, return_offsets_mapping=True,
                     verbose=False)
    inputs = tokenizer(code, return_tensors="pt", truncation=True,
                       max_length=max_length, return_offsets_mapping=True)
    offsets = inputs.pop("offset_mapping")[0].tolist()
    full_offsets = full["offset_mapping"]
    token_to_line = map_tokens_to_lines(code, offsets)
    full_map = map_tokens_to_lines(code, full_offsets)
    num_lines = len(code.split('\n'))
    expected = [Counter() for _ in range(num_lines)]
    retained = [Counter() for _ in range(num_lines)]
    for t, q in full_map.items():
        if q >= 0:
            expected[q][tuple(full_offsets[t])] += 1
    for t, q in token_to_line.items():
        if q >= 0:
            retained[q][tuple(offsets[t])] += 1
    valid_lines = {q for q in range(num_lines)
                   if expected[q] and expected[q] == retained[q]}
    truncated_lines = {q for q in range(num_lines)
                       if expected[q] != retained[q]}
    return inputs, token_to_line, valid_lines, truncated_lines


def aggregate_region_activations(activations, token_to_line, region_lines, num_lines):
    """Separate token-weighted selection from equal-line-weighted direction."""
    region = set(region_lines)
    token_ids = [t for t, q in token_to_line.items() if q in region]
    valid_lines = sorted(region.intersection(token_to_line.values()) - {-1})
    if not token_ids or not valid_lines:
        raise ValueError("Region has no valid token-bearing lines")
    line_acts = get_line_level_activations(activations, token_to_line, num_lines)
    return activations[token_ids].mean(dim=0), line_acts[valid_lines].mean(dim=0)


def map_tokens_to_lines(code, offsets):
    """
    Map each token index to a line number (0-indexed).
    Special tokens (start=end=0) are mapped to -1.
    """
    line_starts = [0]
    for i, char in enumerate(code):
        if char == '\n':
            line_starts.append(i + 1)
            
    def get_line_from_char(char_idx):
        return max(0, bisect_right(line_starts, char_idx) - 1)

    token_to_line = {}
    for token_idx, (start, end) in enumerate(offsets):
        if start == end: # special tokens like <s>, </s>
            token_to_line[token_idx] = -1
        else:
            token_to_line[token_idx] = get_line_from_char(start)
            
    return token_to_line

def get_line_level_activations(activations, token_to_line, num_lines):
    """
    Aggregate token activations into line-level activations.
    activations: Tensor of shape (seq_len, hidden_size)
    token_to_line: dict mapping token_idx to line_idx
    num_lines: total number of lines in the code snippet
    
    Returns: Tensor of shape (num_lines, hidden_size)
    """
    hidden_size = activations.shape[1]
    line_acts = activations.new_zeros((num_lines, hidden_size))
    token_counts = activations.new_zeros((num_lines, 1))
    
    for token_idx, line_idx in token_to_line.items():
        if line_idx < 0 or line_idx >= num_lines:
            continue
        
        line_acts[line_idx] += activations[token_idx]
        token_counts[line_idx] += 1
        
    # Mean pooling as defined in plan.tex; alternative pooling can be explored later.
    # Lines without mapped tokens retain zero as a placeholder.
    return line_acts / token_counts.clamp_min(1)
