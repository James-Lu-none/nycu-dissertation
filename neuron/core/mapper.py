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
