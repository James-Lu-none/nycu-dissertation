import os
import argparse
import json
import torch
import difflib
import numpy as np
from tqdm import tqdm
from transformers import RobertaTokenizerFast, RobertaModel

from core.hook_utils import ActivationExtractor
from core.mapper import (get_line_level_activations, prepare_code_input,
                         aggregate_region_activations)
from core.regions import get_aligned_regions
from core.attribution import get_vulnerability_specific_neurons
from core.direction import (compute_line_representation, score_target_line,
                            compute_pairwise_vulnerability_direction)
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

def print_dataset_summary(vul_data, ben_data, tokenizer, max_length=512):
    """Report full token lengths; pair bins use the longer side of each pair."""
    from collections import Counter

    if len(vul_data) != len(ben_data):
        raise ValueError("Vulnerable and patched datasets must have equal lengths")
    pair_lengths = [
        tuple(len(tokenizer(code, truncation=False, verbose=False)['input_ids'])
              for code in pair)
        for pair in tqdm(zip(vul_data, ben_data), total=len(vul_data),
                         desc="Counting dataset tokens")
    ]
    v_bins = Counter(v // 100 for v, _ in pair_lengths)
    p_bins = Counter(p // 100 for _, p in pair_lengths)
    pair_bins = Counter(max(v, p) // 100 for v, p in pair_lengths)
    excluded_bins = Counter(max(v, p) // 100 for v, p in pair_lengths
                            if max(v, p) > max_length)
    print("\nDataset token distribution (includes special tokens; no truncation)")
    print(f"Vulnerable functions: {len(vul_data)} | Patched functions: {len(ben_data)}")
    print("Pair bins use max(vulnerable tokens, patched tokens).")
    print(f"{'Tokens':>13} | {'Vulnerable':>10} | {'Patched':>10} | {'Pairs':>8} | {'Excluded pairs':>14}")
    for bucket in range(max(pair_bins, default=0) + 1):
        label = f"{bucket * 100}-{bucket * 100 + 99}"
        print(f"{label:>13} | {v_bins[bucket]:10d} | {p_bins[bucket]:10d} | "
              f"{pair_bins[bucket]:8d} | {excluded_bins[bucket]:14d}")
    v_only = sum(v > max_length and p <= max_length for v, p in pair_lengths)
    p_only = sum(p > max_length and v <= max_length for v, p in pair_lengths)
    both = sum(v > max_length and p > max_length for v, p in pair_lengths)
    excluded = v_only + p_only + both
    print(f"Length limit: <= {max_length} tokens per complete function (exactly {max_length} is allowed)")
    print(f"Total pairs: {len(pair_lengths)} | Excluded by length: {excluded} | "
          f"Pass length filter: {len(pair_lengths) - excluded}")
    print(f"Overlength: vulnerable only={v_only}, patched only={p_only}, both={both}")
    print("Unchanged/empty-region exclusions are reported after activation extraction.", flush=True)
    return pair_lengths


def get_modified_lines(vul_code, ben_code):
    matcher = difflib.SequenceMatcher(None, vul_code.split('\n'), ben_code.split('\n'), autojunk=False)
    vul_changed = []
    ben_changed = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ('replace', 'delete'): vul_changed.extend(range(i1, i2))
        if tag in ('replace', 'insert'): ben_changed.extend(range(j1, j2))
    return vul_changed, ben_changed

def extract_all_layers(vul_data, ben_data, tokenizer, model, layers_to_probe,
                       context_lines=1, max_length=512, pair_lengths=None):
    if len(vul_data) != len(ben_data):
        raise ValueError("Vulnerable and patched datasets must have equal lengths")
    if pair_lengths is not None and len(pair_lengths) != len(vul_data):
        raise ValueError("Token length counts must match dataset length")
    if context_lines < 0:
        raise ValueError("context_lines must be nonnegative")
    # Remove overlength pairs before starting the activation progress bar.
    # Keep original indices for selecting inference examples later.
    if pair_lengths is None:
        pair_lengths = [
            tuple(len(tokenizer(code, truncation=False, verbose=False)['input_ids'])
                  for code in pair)
            for pair in zip(vul_data, ben_data)
        ]
    eligible_indices = [i for i, lengths in enumerate(pair_lengths)
                        if all(length <= max_length for length in lengths)]
    extractors = {l: ActivationExtractor(model, l) for l in layers_to_probe}
    # Each pair has two distinct summaries: token mean for selection, line mean
    # for direction. Projection is linear, so projecting the latter equals the
    # mean of the individual line representations after selecting neurons.
    summaries = {
        side: {kind: {l: [] for l in layers_to_probe}
               for kind in ('token_mean', 'line_mean')}
        for side in ('vulnerable', 'patched')
    }
    stats = dict(total=len(vul_data), retained=0, skipped_no_changes=0,
                 skipped_overlength_function=len(vul_data) - len(eligible_indices),
                 skipped_empty_region=0)
    retained_indices = []
    try:
        with torch.no_grad():
            for pair_idx in tqdm(eligible_indices, total=len(eligible_indices),
                                 desc="Extracting Activations"):
                vul_code, ben_code = vul_data[pair_idx], ben_data[pair_idx]
                if vul_code == ben_code:
                    stats['skipped_no_changes'] += 1
                    continue
                regions = get_aligned_regions(vul_code, ben_code, context_lines)
                prepared = [prepare_code_input(code, tokenizer, max_length)
                            for code in (vul_code, ben_code)]
                valid_regions = [sorted(set(region) & data[2])
                                 for region, data in zip(regions, prepared)]
                if any(not region for region in valid_regions):
                    stats['skipped_empty_region'] += 1
                    continue
                for side, code, region, data in zip(
                        ('vulnerable', 'patched'), (vul_code, ben_code),
                        valid_regions, prepared):
                    inputs, token_to_line, _, _ = data
                    for ext in extractors.values():
                        ext.clear()
                    model(**{k: v.to(model.device) for k, v in inputs.items()})
                    for l, ext in extractors.items():
                        acts = ext.activations[f"encoder.layer.{l}.intermediate"][0]
                        token_mean, line_mean = aggregate_region_activations(
                            acts, token_to_line, region, len(code.split('\n')))
                        summaries[side]['token_mean'][l].append(token_mean)
                        summaries[side]['line_mean'][l].append(line_mean)
                stats['retained'] += 1
                retained_indices.append(pair_idx)
        print("Pair filtering: " + json.dumps(stats))
        if not stats['retained']:
            raise ValueError("No valid training pairs remain after region filtering")
        for side in summaries.values():
            for kind in side.values():
                for l in layers_to_probe:
                    kind[l] = torch.stack(kind[l])
        return summaries, extractors, stats, retained_indices
    except Exception:
        for ext in extractors.values():
            ext.remove_hooks()
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--context-lines', type=int, default=1,
                        help='Matched context lines on each side of a diff hunk (default: 1)')
    args = parser.parse_args()
    if args.context_lines < 0:
        parser.error('--context-lines must be nonnegative')
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("Loading CodeBERT tokenizer...")
    tokenizer = RobertaTokenizerFast.from_pretrained("microsoft/codebert-base")

    # Probe all 12 layers of CodeBERT!
    layers_to_probe = list(range(12))

    print("Loading datasets...")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    vul_data = load_dataset(os.path.join(base_dir, "dataset", "vulnerable.jsonl"))
    ben_data = load_dataset(os.path.join(base_dir, "dataset", "benign.jsonl"))
    pair_lengths = print_dataset_summary(vul_data, ben_data, tokenizer)

    print(f"Loading CodeBERT model on {device}...")
    model = RobertaModel.from_pretrained("microsoft/codebert-base", attn_implementation="eager").to(device)
    model.eval()

    print(f"Extracting aligned regions with context N={args.context_lines} across {layers_to_probe}...")
    summaries, extractors, stats, retained_indices = extract_all_layers(
        vul_data, ben_data, tokenizer, model, layers_to_probe,
        context_lines=args.context_lines, pair_lengths=pair_lengths)

    print("Calculating vulnerability directions (d_v) for all layers...")
    layer_directions = {}
    
    for l in layers_to_probe:
        down_proj = extractors[l].get_down_projection_weights()
        v_token_means = summaries['vulnerable']['token_mean'][l]
        b_token_means = summaries['patched']['token_mean'][l]
        target_neurons = get_vulnerability_specific_neurons(
            v_token_means, b_token_means, down_proj, k_ratio=0.10)

        # Equal weight per valid line within each side, then equal weight per pair.
        vul_reps = torch.stack([compute_line_representation(a, target_neurons, down_proj)
                               for a in summaries['vulnerable']['line_mean'][l]])
        ben_reps = torch.stack([compute_line_representation(a, target_neurons, down_proj)
                               for a in summaries['patched']['line_mean'][l]])
        d_v = compute_pairwise_vulnerability_direction(vul_reps, ben_reps)
        if torch.norm(d_v) > 0:
            d_v = d_v / torch.norm(d_v)
            
        #  project representation on to vul direction d_v
        v_scores = score_target_line(vul_reps, d_v).cpu().numpy()
        b_scores = score_target_line(ben_reps, d_v).cpu().numpy()
            
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
    test_idx = retained_indices[0]
    for i in retained_indices:
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
        
        inputs, token_to_line, valid_lines, _ = prepare_code_input(
            code_snippet, tokenizer, max_length=512)
        inputs = {k: v.to(model.device) for k, v in inputs.items()}
        
        with torch.no_grad():
            for ext in extractors.values(): ext.clear()
            model(**inputs)
            
        num_lines = len(code_snippet.split('\n'))
        lines = code_snippet.split('\n')
        
        # Save line activations before the attention forward overwrites hooks.
        line_acts_by_layer = {
            l: get_line_level_activations(
                extractors[l].activations[f"encoder.layer.{l}.intermediate"][0],
                token_to_line, num_lines)
            for l in layers_to_probe
        }
        # Attention baseline uses the same truncation and validity policy.
        a_scores = calculate_line_attention_scores(code_snippet, model, tokenizer)
        finite_scores = a_scores[torch.isfinite(a_scores)]
        if finite_scores.numel():
            a_scores = a_scores / (finite_scores.max() + 1e-9)
        
        for q in range(num_lines):
            if q not in valid_lines:
                print(f"Line {q+1:2d} | A-Score: 未評分 | N-Score: 未評分 | {lines[q]}")
                continue
            # Calculate score for this line across all layers
            layer_scores = []
            for l in layers_to_probe:
                line_acts = line_acts_by_layer[l]
                
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
    for ext in extractors.values():
        ext.remove_hooks()

if __name__ == "__main__":
    main()
