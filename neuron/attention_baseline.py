import torch
from transformers import RobertaTokenizerFast, RobertaModel
from core.mapper import prepare_code_input

def calculate_line_attention_scores(test_code, model, tokenizer):
    """
    Calculate Line-Level Attention Scores using the standard method from Attention-based directed fuzzing.
    """
    inputs, token_to_line, valid_lines, _ = prepare_code_input(
        test_code, tokenizer, max_length=512)
    inputs = {k: v.to(model.device) for k, v in inputs.items()}
    
    # Enable output_attentions to extract the attention matrices
    with torch.no_grad():
        outputs = model(**inputs, output_attentions=True)
        
    # outputs.attentions is a tuple of 12 layers
    # Each layer is a tensor of shape (batch_size, num_heads, seq_len, seq_len)
    # CodeBERT base has 12 layers and 12 attention heads
    attentions = torch.stack(outputs.attentions) # shape: (12, 1, 12, seq_len, seq_len)
    
    # 1. Average attention across all layers and all heads
    # shape becomes (seq_len, seq_len)
    avg_attention = attentions.mean(dim=(0, 1, 2))
    
    # 2. Calculate Token-Level Attention Score
    # We use the "Column Sum" approach (Global Pooling): 
    # How much attention does token 'i' receive from ALL other tokens in the sequence?
    token_attention_scores = avg_attention.sum(dim=0) # shape: (seq_len,)
    
    # Alternatively, you could use the CLS token's attention to other tokens:
    # token_attention_scores = avg_attention[0, :]
    
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
    print("Loading Base CodeBERT model (No Fine-tuning)...")
    tokenizer = RobertaTokenizerFast.from_pretrained("microsoft/codebert-base")
    model = RobertaModel.from_pretrained("microsoft/codebert-base", attn_implementation="eager")
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
