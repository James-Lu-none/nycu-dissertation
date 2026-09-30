import torch
from transformers import AutoTokenizer
from core.model_config import MODEL_ID, MAX_LENGTH, load_encoder
from core.mapper import prepare_code_input

def calculate_line_attention_scores(test_code, model, tokenizer, max_length=MAX_LENGTH):
    """
    Calculate Line-Level Attention Scores using the standard method from Attention-based directed fuzzing.
    """
    inputs, token_to_line, valid_lines, _ = prepare_code_input(
        test_code, tokenizer, max_length=max_length)
    inputs = {k: v.to(model.device) for k, v in inputs.items()}
    
    # Reduce each attention layer immediately, rather than retain all L*T*T maps.
    # Eager is required for explicit attention probabilities.
    total = None
    count = 0
    def collect(module, args, output):
        nonlocal total, count
        weights = output[1]
        if weights is None:
            raise ValueError('Attention probabilities unavailable')
        column = weights.float().mean(dim=(0, 1)).sum(dim=0)
        total = column if total is None else total + column
        count += 1
        return (output[0], None)

    previous = model.config._attn_implementation
    hooks = []
    try:
        model.config._attn_implementation = 'eager'
        for layer in model.layers:
            hooks.append(layer.attn.register_forward_hook(collect))
        with torch.no_grad():
            model(**inputs, output_attentions=True)
    finally:
        for hook in hooks:
            hook.remove()
        model.config._attn_implementation = previous
    if not count:
        raise ValueError('No attention layers captured')
    token_attention_scores = total / count

    # 3. Map tokens to lines and aggregate
    num_lines = len(test_code.split('\n'))
    
    line_scores = torch.zeros(num_lines, device=token_attention_scores.device)
    
    for token_idx, line_idx in token_to_line.items():
        if line_idx == -1 or line_idx >= num_lines:
            continue
        # For attention, we typically SUM the attention weights of all tokens in the line
        line_scores[line_idx] += token_attention_scores[token_idx]
        
    # NaN denotes an unscored line, not zero evidence of vulnerability.
    for q in range(num_lines):
        if q not in valid_lines:
            line_scores[q] = float('nan')
    return line_scores

def main():
    print("Loading Base ModernBERT model (No Fine-tuning)...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = load_encoder()
    model.eval()

    test_code = (
        "void copy(char *src) {\n"
        "  char dest[10];\n"
        "  strcpy(dest, src);\n"
        "}"
    )
    
    print("\n" + "="*60)
    print("Testing Attention Baseline on Snippet:")
    print(test_code)
    print("-" * 60)
    
    line_scores = calculate_line_attention_scores(test_code, model, tokenizer)
    
    # Normalize scores for better readability (0 to 1)
    finite_scores = line_scores[torch.isfinite(line_scores)]
    if finite_scores.numel():
        line_scores = line_scores / (finite_scores.max() + 1e-9)
    
    lines = test_code.split('\n')
    print("Traditional Attention Scores (Baseline):")
    for q in range(len(lines)):
        score = f"{line_scores[q].item():7.4f}" if torch.isfinite(line_scores[q]) else "N.A."
        print(f"Line {q+1:2d} | Score: {score} | {lines[q]}")
    print("="*60 + "\n")
    
    print("Interpretation:")
    print("Notice how traditional Attention assigns high scores to structural lines (like '{' or '}')")
    print("or variable declarations, because attention is heavily influenced by syntax.")
    print("Without fine-tuning on vulnerability data, it cannot single out 'strcpy' as dangerous.")

if __name__ == "__main__":
    main()
