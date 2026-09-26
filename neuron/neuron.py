import os
import json
import torch
import difflib
from tqdm import tqdm
from transformers import RobertaTokenizerFast, RobertaModel

from core.hook_utils import ActivationExtractor
from core.mapper import map_tokens_to_lines, get_line_level_activations
from core.attribution import calculate_neuron_contributions, get_vulnerability_specific_neurons
from core.direction import compute_line_representation, compute_vulnerability_direction, score_target_line
from attention_baseline import calculate_line_attention_scores

def load_dataset(file_path):
    data = []
    with open(file_path, 'r') as f:
        for line in f:
            data.append(json.loads(line)['code'])
    return data

def get_modified_lines(vul_code, ben_code):
    vul_lines = vul_code.split('\n')
    ben_lines = ben_code.split('\n')
    
    matcher = difflib.SequenceMatcher(None, vul_lines, ben_lines)
    vul_changed_indices = []
    ben_changed_indices = []
    
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ('replace', 'delete'):
            vul_changed_indices.extend(range(i1, i2))
        if tag in ('replace', 'insert'):
            ben_changed_indices.extend(range(j1, j2))
            
    return vul_changed_indices, ben_changed_indices

def extract_paired_activations(vul_data, ben_data, tokenizer, model, extractor, target_layer):
    """
    Extracts line-level activations strictly for the MODIFIED lines in the dataset pairs.
    """
    vul_acts_list = []
    ben_acts_list = []
    
    with torch.no_grad():
        for vul_code, ben_code in tqdm(zip(vul_data, ben_data), total=len(vul_data), desc="Extracting Activations"):
            vul_changed, ben_changed = get_modified_lines(vul_code, ben_code)
            
            # Fallback if diff fails
            if not vul_changed: vul_changed = list(range(len(vul_code.split('\n'))))
            if not ben_changed: ben_changed = list(range(len(ben_code.split('\n'))))
            
            # Process Vulnerable snippet
            inputs_v = tokenizer(vul_code, return_tensors="pt", truncation=True, max_length=512, return_offsets_mapping=True)
            offsets_v = inputs_v.pop("offset_mapping")[0].tolist()
            extractor.clear()
            model(**inputs_v)
            token_acts_v = extractor.activations[target_layer][0]
            num_lines_v = len(vul_code.split('\n'))
            t2l_v = map_tokens_to_lines(vul_code, offsets_v)
            line_acts_v = get_line_level_activations(token_acts_v, t2l_v, num_lines_v)
            
            # Aggregate ONLY over modified vulnerable lines
            vul_act = line_acts_v[vul_changed].mean(dim=0)
            vul_acts_list.append(vul_act)
            
            # Process Benign snippet
            inputs_b = tokenizer(ben_code, return_tensors="pt", truncation=True, max_length=512, return_offsets_mapping=True)
            offsets_b = inputs_b.pop("offset_mapping")[0].tolist()
            extractor.clear()
            model(**inputs_b)
            token_acts_b = extractor.activations[target_layer][0]
            num_lines_b = len(ben_code.split('\n'))
            t2l_b = map_tokens_to_lines(ben_code, offsets_b)
            line_acts_b = get_line_level_activations(token_acts_b, t2l_b, num_lines_b)
            
            # Aggregate ONLY over modified benign lines
            ben_act = line_acts_b[ben_changed].mean(dim=0)
            ben_acts_list.append(ben_act)
            
    return torch.stack(vul_acts_list), torch.stack(ben_acts_list)

def main():
    print("Loading CodeBERT model...")
    tokenizer = RobertaTokenizerFast.from_pretrained("microsoft/codebert-base")
    model = RobertaModel.from_pretrained("microsoft/codebert-base")
    model.eval()

    # Configurable layer L
    target_layer_idx = 10
    target_layer_name = f"encoder.layer.{target_layer_idx}.intermediate"
    
    extractor = ActivationExtractor(model, target_layer_idx)
    down_proj_weights = extractor.get_down_projection_weights() # shape: (3072, 768)

    print("Loading datasets...")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    vul_data = load_dataset(os.path.join(base_dir, "dataset", "vulnerable.jsonl"))
    ben_data = load_dataset(os.path.join(base_dir, "dataset", "benign.jsonl"))

    print(f"Extracting line-level activations strictly from modified lines...")
    vul_acts, ben_acts = extract_paired_activations(vul_data, ben_data, tokenizer, model, extractor, target_layer_name)

    print("Calculating neuron contributions and finding N_r,l...")
    vul_contributions = calculate_neuron_contributions(vul_acts, down_proj_weights)
    ben_contributions = calculate_neuron_contributions(ben_acts, down_proj_weights)
    
    # Increase K ratio to 10% to capture more complex vulnerability semantics
    target_neurons = get_vulnerability_specific_neurons(vul_contributions, ben_contributions, k_ratio=0.10)
    print(f"Found {len(target_neurons)} vulnerability-specific neurons in N_r,l.")

    print("Computing line-level representations in N_r,l space...")
    vul_reps = torch.stack([compute_line_representation(act, target_neurons, down_proj_weights) for act in vul_acts])
    ben_reps = torch.stack([compute_line_representation(act, target_neurons, down_proj_weights) for act in ben_acts])

    print("Calculating vulnerability direction d_v...")
    d_v = compute_vulnerability_direction(vul_reps, ben_reps) # Method A: Global Average
    
    # ---------------------------------------------------------
    # Inference Phase: Real World Code Snippet (Before and After Patch)
    # ---------------------------------------------------------
    # Find a relatively large snippet from our dataset for testing
    test_idx = 0
    for i in range(len(vul_data)):
        if len(vul_data[i].split('\n')) > 10 and len(ben_data[i].split('\n')) > 10:
            test_idx = i
            break
            
    test_codes = {
        "Vulnerable (Before Patch)": vul_data[test_idx],
        "Secure (After Patch)": ben_data[test_idx]
    }
    
    vul_changed_test, ben_changed_test = get_modified_lines(test_codes["Vulnerable (Before Patch)"], test_codes["Secure (After Patch)"])
    RED = '\033[91m'
    GREEN = '\033[92m'
    RESET = '\033[0m'
    
    for label, code_snippet in test_codes.items():
        is_vul = "Vulnerable" in label
        changed_lines = vul_changed_test if is_vul else ben_changed_test
        color = RED if is_vul else GREEN
        
        print("\n" + "="*100)
        print(f"Testing Inference on: {label}")
        print("-" * 100)
        print("Line  | Neuron Score | Attention Score | Code")
        print("-" * 100)
        
        inputs = tokenizer(code_snippet, return_tensors="pt", return_offsets_mapping=True, truncation=True, max_length=512)
        offsets = inputs.pop("offset_mapping")[0].tolist()
        
        with torch.no_grad():
            extractor.clear()
            model(**inputs)
            test_acts = extractor.activations[target_layer_name][0]
            
        num_lines = len(code_snippet.split('\n'))
        token_to_line = map_tokens_to_lines(code_snippet, offsets)
        line_acts = get_line_level_activations(test_acts, token_to_line, num_lines)
        lines = code_snippet.split('\n')
        
        # Calculate Attention Scores
        a_scores = calculate_line_attention_scores(code_snippet, model, tokenizer)
        a_scores = a_scores / (a_scores.max() + 1e-9)
        
        for q in range(num_lines):
            p_q = compute_line_representation(line_acts[q], target_neurons, down_proj_weights)
            n_score = score_target_line(p_q, d_v)
            a_score = a_scores[q].item()
            
            code_line = lines[q]
            if q in changed_lines:
                code_line = f"{color}{code_line}{RESET}"
                
            print(f"Line {q+1:2d} | N-Score: {n_score.item():7.4f} | A-Score: {a_score:7.4f} | {code_line}")
        print("="*100)

if __name__ == "__main__":
    main()
