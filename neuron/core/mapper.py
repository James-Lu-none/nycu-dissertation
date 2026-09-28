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
        for line_idx in range(len(line_starts)-1, -1, -1):
            if char_idx >= line_starts[line_idx]:
                return line_idx
        return 0

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
    import torch
    
    hidden_size = activations.shape[1]
    # Initialize with negative infinity for max pooling
    line_acts = torch.full((num_lines, hidden_size), -float('inf'))
    
    for token_idx, line_idx in token_to_line.items():
        if line_idx == -1 or line_idx >= num_lines:
            continue
        
        # CHANGED: Use Max pooling instead of Mean
        # This prevents the strong signal of vulnerability tokens (like strcpy) 
        # from being washed out by other common tokens in the same line.
        line_acts[line_idx] = torch.max(line_acts[line_idx], activations[token_idx])
        
    # Replace -inf with 0 for empty lines (lines with no tokens mapped)
    line_acts[line_acts == -float('inf')] = 0.0
    
    return line_acts
