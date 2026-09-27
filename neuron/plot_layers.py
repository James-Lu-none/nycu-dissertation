import os
import json
import torch
import difflib
import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from tqdm import tqdm
from transformers import RobertaTokenizerFast, RobertaModel

from core.hook_utils import ActivationExtractor
from core.mapper import map_tokens_to_lines, get_line_level_activations
from core.attribution import calculate_neuron_contributions, get_vulnerability_specific_neurons
from core.direction import compute_line_representation

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
    # Hook all target layers simultaneously
    extractors = {l: ActivationExtractor(model, l) for l in layers_to_probe}
    
    vul_acts_by_layer = {l: [] for l in layers_to_probe}
    ben_acts_by_layer = {l: [] for l in layers_to_probe}
    
    with torch.no_grad():
        for vul_code, ben_code in tqdm(zip(vul_data, ben_data), total=len(vul_data), desc="Extracting Layers"):
            vul_changed, ben_changed = get_modified_lines(vul_code, ben_code)
            if not vul_changed: vul_changed = list(range(len(vul_code.split('\n'))))
            if not ben_changed: ben_changed = list(range(len(ben_code.split('\n'))))
            
            # --- Vulnerable ---
            inputs_v = tokenizer(vul_code, return_tensors="pt", truncation=True, max_length=512, return_offsets_mapping=True)
            offsets_v = inputs_v.pop("offset_mapping")[0].tolist()
            for ext in extractors.values(): ext.clear()
            model(**inputs_v)
            
            t2l_v = map_tokens_to_lines(vul_code, offsets_v)
            num_lines_v = len(vul_code.split('\n'))
            
            for l, ext in extractors.items():
                token_acts_v = ext.activations[f"encoder.layer.{l}.intermediate"][0]
                line_acts_v = get_line_level_activations(token_acts_v, t2l_v, num_lines_v)
                vul_acts_by_layer[l].append(line_acts_v[vul_changed].max(dim=0)[0])
                
            # --- Benign ---
            inputs_b = tokenizer(ben_code, return_tensors="pt", truncation=True, max_length=512, return_offsets_mapping=True)
            offsets_b = inputs_b.pop("offset_mapping")[0].tolist()
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
    print("Loading Base CodeBERT model...")
    tokenizer = RobertaTokenizerFast.from_pretrained("microsoft/codebert-base")
    model = RobertaModel.from_pretrained("microsoft/codebert-base")
    model.eval()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    vul_data = load_dataset(os.path.join(base_dir, "dataset", "vulnerable.jsonl"))
    ben_data = load_dataset(os.path.join(base_dir, "dataset", "benign.jsonl"))
    
    # Define which layers to look at (0-indexed, CodeBERT has 12 layers: 0 to 11)
    layers_to_probe = [2, 5, 8, 10, 11]
    
    print(f"Extracting representations across layers {layers_to_probe} in one pass...")
    vul_acts, ben_acts, extractors = extract_all_layers(vul_data, ben_data, tokenizer, model, layers_to_probe)
    
    fig, axes = plt.subplots(1, len(layers_to_probe), figsize=(4 * len(layers_to_probe), 4))
    if len(layers_to_probe) == 1:
        axes = [axes]
        
    for idx, l in enumerate(layers_to_probe):
        down_proj = extractors[l].get_down_projection_weights()
        
        v_acts = vul_acts[l]
        b_acts = ben_acts[l]
        
        v_contrib = calculate_neuron_contributions(v_acts, down_proj)
        b_contrib = calculate_neuron_contributions(b_acts, down_proj)
        
        # Since we use Set Difference (N_r = N_v - N_p), a small k_ratio results in too few neurons.
        # We need a larger k_ratio (e.g., 30%) so the difference set yields enough capacity (e.g., ~100 neurons).
        target_neurons = get_vulnerability_specific_neurons(v_contrib, b_contrib, k_ratio=0.30)
        
        vul_reps = torch.stack([compute_line_representation(a, target_neurons, down_proj) for a in v_acts])
        ben_reps = torch.stack([compute_line_representation(a, target_neurons, down_proj) for a in b_acts])
        
        # Calculate d_v for this layer
        d_v = vul_reps.mean(dim=0) - ben_reps.mean(dim=0)
        if torch.norm(d_v) > 0:
            d_v = d_v / torch.norm(d_v)
            
        # Compute projection scores (N-Score)
        v_scores = (vul_reps @ d_v).cpu().numpy()
        b_scores = (ben_reps @ d_v).cpu().numpy()
        
        # Calculate metrics
        mean_diff = np.mean(v_scores) - np.mean(b_scores)
        
        info_text = (
            f"|N_r,l|: {len(target_neurons)}\n"
            f"Mean Diff: {mean_diff:.2f}\n"
            f"N: {len(vul_reps)} pairs"
        )
        
        ax = axes[idx]
        
        # Plot Histograms
        ax.hist(v_scores, bins=30, alpha=0.5, color='red', label='Vulnerable', density=True)
        ax.hist(b_scores, bins=30, alpha=0.5, color='blue', label='Secure', density=True)
        
        ax.set_title(f"Layer {l}")
        ax.set_yticks([])
        ax.set_xlabel("N-Score ($d_v$ Projection)")
        
        # Add text box with metrics
        ax.text(0.05, 0.95, info_text, transform=ax.transAxes, fontsize=10,
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
        
    axes[-1].legend(loc='upper right')
    plt.tight_layout()
    output_path = "multi_layer_projection.png"
    plt.savefig(output_path, dpi=300)
    print(f"\nSaved multi-layer projection plot to {output_path}")

if __name__ == "__main__":
    main()
