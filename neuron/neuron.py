import os
import json
import torch
import difflib
import numpy as np
from tqdm import tqdm
from transformers import RobertaTokenizerFast, RobertaModel

from core.hook_utils import ActivationExtractor
from core.mapper import map_tokens_to_lines, get_line_level_activations
from core.attribution import calculate_neuron_contributions, get_vulnerability_specific_neurons
from core.direction import compute_line_representation, score_target_line
from attention_baseline import calculate_line_attention_scores

def plot_all_layers(layer_directions, output_path="multi_layer_projection.png"):
    import matplotlib.pyplot as plt
    import numpy as np
    
    num_layers = len(layer_directions)
    cols = 4
    rows = (num_layers + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4 * cols, 3 * rows))
    if num_layers == 1:
        axes = [axes]
    else:
        axes = axes.flatten()
    
    for idx, (l, info) in enumerate(layer_directions.items()):
        ax = axes[idx]
        v_scores = info['v_scores']
        b_scores = info['b_scores']
        
        mean_diff = np.mean(v_scores) - np.mean(b_scores)
        info_text = (
            f"|N_r,l|: {len(info['target_neurons'])}\n"
            f"Mean Diff: {mean_diff:.2f}\n"
            f"N: {len(v_scores)} pairs"
        )
        
        ax.hist(v_scores, bins=30, alpha=0.5, color='red', label='Vulnerable', density=True)
        ax.hist(b_scores, bins=30, alpha=0.5, color='blue', label='Secure', density=True)
        
        ax.set_title(f"Layer {l}")
        ax.set_yticks([])
        ax.set_xlabel("N-Score ($d_v$ Projection)")
        ax.text(0.05, 0.95, info_text, transform=ax.transAxes, fontsize=9,
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
        if idx == 0:
            ax.legend(loc='upper right', fontsize=8)
            
    for i in range(num_layers, len(axes)):
        fig.delaxes(axes[i])
        
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    print(f"[+] Saved multi-layer projection plot to {output_path}")

def plot_all_layers_pca(layer_directions, output_path="multi_layer_pca.png"):
    import matplotlib.pyplot as plt
    from sklearn.decomposition import PCA
    import numpy as np
    
    num_layers = len(layer_directions)
    cols = 4
    rows = (num_layers + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4 * cols, 3 * rows))
    if num_layers == 1:
        axes = [axes]
    else:
        axes = axes.flatten()
        
    for idx, (l, info) in enumerate(layer_directions.items()):
        ax = axes[idx]
        vul_reps = info['vul_reps']
        ben_reps = info['ben_reps']
        
        all_reps = np.vstack((vul_reps, ben_reps))
        pca = PCA(n_components=2)
        pca_result = pca.fit_transform(all_reps)
        
        v_pca = pca_result[:len(vul_reps)]
        b_pca = pca_result[len(vul_reps):]
        
        ax.scatter(v_pca[:, 0], v_pca[:, 1], c='red', label='Vulnerable', alpha=0.5, s=10)
        ax.scatter(b_pca[:, 0], b_pca[:, 1], c='blue', label='Secure', alpha=0.5, s=10)
        
        ax.set_title(f"Layer {l}")
        ax.set_xticks([])
        ax.set_yticks([])
        
        if idx == 0:
            ax.legend(loc='upper right', fontsize=8)
            
    for i in range(num_layers, len(axes)):
        fig.delaxes(axes[i])
        
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    print(f"[+] Saved multi-layer PCA plot to {output_path}")

def load_dataset(file_path):
    data = []
    with open(file_path, 'r') as f:
        for line in f:
            data.append(json.loads(line)['code'])
    return data

def get_modified_lines(vul_code, ben_code):
    matcher = difflib.SequenceMatcher(None, vul_code.split('\n'), ben_code.split('\n'))
    vul_changed = []
    ben_changed = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ('replace', 'delete'): vul_changed.extend(range(i1, i2))
        if tag in ('replace', 'insert'): ben_changed.extend(range(j1, j2))
    return vul_changed, ben_changed

def extract_all_layers(vul_data, ben_data, tokenizer, model, layers_to_probe):
    extractors = {l: ActivationExtractor(model, l) for l in layers_to_probe}
    vul_acts_by_layer = {l: [] for l in layers_to_probe}
    ben_acts_by_layer = {l: [] for l in layers_to_probe}
    
    with torch.no_grad():
        for vul_code, ben_code in tqdm(zip(vul_data, ben_data), total=len(vul_data), desc="Extracting Activations"):
            vul_changed, ben_changed = get_modified_lines(vul_code, ben_code)
            if not vul_changed: vul_changed = list(range(len(vul_code.split('\n'))))
            if not ben_changed: ben_changed = list(range(len(ben_code.split('\n'))))
            
            # Vulnerable
            inputs_v = tokenizer(vul_code, return_tensors="pt", truncation=True, max_length=512, return_offsets_mapping=True)
            offsets_v = inputs_v.pop("offset_mapping")[0].tolist()
            inputs_v = {k: v.to(model.device) for k, v in inputs_v.items()}
            for ext in extractors.values(): ext.clear()
            model(**inputs_v)
            t2l_v = map_tokens_to_lines(vul_code, offsets_v)
            num_lines_v = len(vul_code.split('\n'))
            
            for l, ext in extractors.items():
                token_acts_v = ext.activations[f"encoder.layer.{l}.intermediate"][0]
                line_acts_v = get_line_level_activations(token_acts_v, t2l_v, num_lines_v)
                vul_acts_by_layer[l].append(line_acts_v[vul_changed].max(dim=0)[0])
                
            # Benign
            inputs_b = tokenizer(ben_code, return_tensors="pt", truncation=True, max_length=512, return_offsets_mapping=True)
            offsets_b = inputs_b.pop("offset_mapping")[0].tolist()
            inputs_b = {k: v.to(model.device) for k, v in inputs_b.items()}
            for ext in extractors.values(): ext.clear()
            model(**inputs_b)
            t2l_b = map_tokens_to_lines(ben_code, offsets_b)
            num_lines_b = len(ben_code.split('\n'))
            
            for l, ext in extractors.items():
                token_acts_b = ext.activations[f"encoder.layer.{l}.intermediate"][0]
                line_acts_b = get_line_level_activations(token_acts_b, t2l_b, num_lines_b)
                ben_acts_by_layer[l].append(line_acts_b[ben_changed].max(dim=0)[0])
                
    for l in layers_to_probe:
        vul_acts_by_layer[l] = torch.stack(vul_acts_by_layer[l])
        ben_acts_by_layer[l] = torch.stack(ben_acts_by_layer[l])
        
    return vul_acts_by_layer, ben_acts_by_layer, extractors

def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Loading CodeBERT model on {device}...")
    tokenizer = RobertaTokenizerFast.from_pretrained("microsoft/codebert-base")
    model = RobertaModel.from_pretrained("microsoft/codebert-base", attn_implementation="eager").to(device)
    model.eval()

    # Probe all 12 layers of CodeBERT!
    layers_to_probe = list(range(12))

    print("Loading datasets...")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    vul_data = load_dataset(os.path.join(base_dir, "dataset", "vulnerable.jsonl"))
    ben_data = load_dataset(os.path.join(base_dir, "dataset", "benign.jsonl"))

    print(f"Extracting line-level activations strictly from modified lines across {layers_to_probe}...")
    vul_acts_dict, ben_acts_dict, extractors = extract_all_layers(vul_data, ben_data, tokenizer, model, layers_to_probe)

    print("Calculating vulnerability directions (d_v) for all layers...")
    layer_directions = {}
    
    for l in layers_to_probe:
        down_proj = extractors[l].get_down_projection_weights()
        v_acts = vul_acts_dict[l]
        b_acts = ben_acts_dict[l]
        
        # Old Set Difference Logic
        # v_contrib = calculate_neuron_contributions(v_acts, down_proj)
        # b_contrib = calculate_neuron_contributions(b_acts, down_proj)
        
        # # Consistent with plot_layers: 30% ratio to maintain capacity after set difference
        # target_neurons = get_vulnerability_specific_neurons(v_contrib, b_contrib, k_ratio=0.30)

        # Pair-wise contribution difference logic
        target_neurons = get_vulnerability_specific_neurons(v_acts, b_acts, down_proj, k_ratio=0.10)
        
        vul_reps = torch.stack([compute_line_representation(a, target_neurons, down_proj) for a in v_acts])
        ben_reps = torch.stack([compute_line_representation(a, target_neurons, down_proj) for a in b_acts])
        
        d_v = vul_reps.mean(dim=0) - ben_reps.mean(dim=0)
        if torch.norm(d_v) > 0:
            d_v = d_v / torch.norm(d_v)
            
        v_scores = torch.nn.functional.cosine_similarity(vul_reps, d_v.unsqueeze(0)).cpu().numpy()
        b_scores = torch.nn.functional.cosine_similarity(ben_reps, d_v.unsqueeze(0)).cpu().numpy()
            
        layer_directions[l] = {
            'target_neurons': target_neurons,
            'down_proj': down_proj,
            'd_v': d_v,
            'v_scores': v_scores,
            'b_scores': b_scores,
            'vul_reps': vul_reps.cpu().numpy(),
            'ben_reps': ben_reps.cpu().numpy()
        }
        print(f"Layer {l:2d} | |N_r,l| = {len(target_neurons)}")

    # Generate the comprehensive plot
    print("Generating comprehensive plot for all probed layers...")
    plot_all_layers(layer_directions)
    plot_all_layers_pca(layer_directions)

    # Inference Phase
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
        print("Line  | Attention Score | Ensemble N-Score | Code")
        print("-" * 100)
        
        inputs = tokenizer(code_snippet, return_tensors="pt", return_offsets_mapping=True, truncation=True, max_length=512)
        offsets = inputs.pop("offset_mapping")[0].tolist()
        inputs = {k: v.to(model.device) for k, v in inputs.items()}
        
        with torch.no_grad():
            for ext in extractors.values(): ext.clear()
            model(**inputs)
            
        num_lines = len(code_snippet.split('\n'))
        token_to_line = map_tokens_to_lines(code_snippet, offsets)
        lines = code_snippet.split('\n')
        
        # Attention baseline
        a_scores = calculate_line_attention_scores(code_snippet, model, tokenizer)
        a_scores = a_scores / (a_scores.max() + 1e-9)
        
        for q in range(num_lines):
            # Calculate score for this line across all layers
            layer_scores = []
            for l in layers_to_probe:
                test_acts = extractors[l].activations[f"encoder.layer.{l}.intermediate"][0]
                line_acts = get_line_level_activations(test_acts, token_to_line, num_lines)
                
                info = layer_directions[l]
                p_q = compute_line_representation(line_acts[q], info['target_neurons'], info['down_proj'])
                score = score_target_line(p_q, info['d_v']).item()
                layer_scores.append(score)
                
            # Take the MAXIMUM score across all layers (Ensemble approach)
            ensemble_n_score = max(layer_scores)
            a_score = a_scores[q].item()
            
            code_line = lines[q]
            if q in changed_lines:
                code_line = f"{color}{code_line}{RESET}"
                
            print(f"Line {q+1:2d} | A-Score: {a_score:7.4f} | N-Score: {ensemble_n_score:7.4f} | {code_line}")
        print("="*100)

if __name__ == "__main__":
    main()
