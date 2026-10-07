from core.nonlinear import fit_rbf, plot_delta_clusters
from core.experiment_report import uncertainty, write_csv
from core.direction_consistency import direction_consistency, plot_consistency
from core.linear_directions import fit_linear_candidates
from core.run_output import create_run
from core.model_config import MODELS, MAX_LENGTH, load_encoder, load_tokenizer
import os
import argparse
import json
import torch
import difflib
import numpy as np
from tqdm import tqdm

from core.hook_utils import ActivationExtractor
from core.mapper import (get_line_level_activations, prepare_code_input,
                         aggregate_region_activations)
from core.regions import get_aligned_regions
from core.splits import load_paired_records, split_pairs, load_unified_records
from core.evaluation import evaluate_localization, select_layer
from core.attribution import get_vulnerability_specific_neurons
from core.direction import (compute_line_representation, score_target_line,
                            compute_pairwise_vulnerability_direction)
from attention_baseline import calculate_line_attention_scores

def plot_all_layers(layer_directions, output_path="multi_layer_projection_modernbert.png"):
    import matplotlib.pyplot as plt
    import numpy as np
    
    num_layers = len(layer_directions)
    cols = 4
    rows = (num_layers + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4 * cols, 3 * rows))
    axes = np.asarray(axes).reshape(-1)
    
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

def plot_all_layers_pca(layer_directions, output_path="multi_layer_pca_modernbert.png"):
    import matplotlib.pyplot as plt
    from sklearn.decomposition import PCA
    import numpy as np
    
    num_layers = len(layer_directions)
    cols = 4
    rows = (num_layers + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(4 * cols, 3 * rows))
    axes = np.asarray(axes).reshape(-1)
        
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

def print_dataset_summary(vul_data, ben_data, tokenizer, max_length=MAX_LENGTH):
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
                       context_lines=1, max_length=MAX_LENGTH, pair_lengths=None):
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
                        acts = ext.activation[0]
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
    parser.add_argument('--svm-c-values', type=float, nargs='+', default=[0.1, 1., 10.])
    parser.add_argument('--svm-gammas', type=float, nargs='+', default=[0.0001, 0.001, 0.01])
    parser.add_argument('--bootstrap', type=int, default=1000)
    parser.add_argument('--lda-shrinkages', type=float, nargs='+', default=[0.1, 0.5, 1.0])
    parser.add_argument('--logistic-c-values', type=float, nargs='+', default=[0.01, 0.1, 1.0, 10.0])
    parser.add_argument('--output-dir', help='Parent of timestamped run directories (default: outputs/)')
    parser.add_argument('--model', choices=MODELS, default='modernbert')
    parser.add_argument('--context-lines', type=int, default=1,
                        help='Matched context lines on each side of a diff hunk (default: 1)')
    parser.add_argument('--split-seed', type=int, default=42)
    parser.add_argument('--dataset', type=str, nargs='*', default=None,
                        help='Path(s) to unified JSONL dataset file(s) or directory. Defaults to dataset/source/.')
    parser.add_argument('--cwe', type=str, nargs='+', default=None,
                        help='Optional CWE ID(s) to filter by (e.g. CWE-787).')
    args = parser.parse_args()
    if any(not 0 < x <= 1 for x in args.lda_shrinkages) or any(not 0 < x < float('inf') for x in args.logistic_c_values):
        parser.error('Shrinkage must be in (0, 1]; logistic C must be finite and positive')
    if args.bootstrap < 0 or any(not 0 < v < float('inf') for v in args.svm_c_values + args.svm_gammas):
        parser.error('Invalid bootstrap count or SVM parameters')
    if args.context_lines < 0:
        parser.error('--context-lines must be nonnegative')
    run_dir, run_metadata = create_run(__file__, args.model, args, args.output_dir)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Loading {args.model} tokenizer...")
    tokenizer, revision = load_tokenizer(args.model)



    print("Loading datasets...")
    import glob
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    dataset_paths = args.dataset
    if not dataset_paths:
        dataset_paths = [os.path.join(base_dir, "dataset", "source")]
        
    records = []
    for path in dataset_paths:
        if os.path.isdir(path):
            jsonl_files = glob.glob(os.path.join(path, "*.jsonl"))
            for jf in jsonl_files:
                records.extend(load_unified_records(jf, cwe_filter=args.cwe))
        elif os.path.isfile(path):
            records.extend(load_unified_records(path, cwe_filter=args.cwe))
        else:
            print(f"Warning: Dataset path not found: {path}")
            
    print(f"Loaded {len(records)} pairs across {len(dataset_paths)} specified paths.")
    
    vul_data = [v['code'] for v, _ in records]
    ben_data = [p['code'] for _, p in records]
    pair_lengths = print_dataset_summary(vul_data, ben_data, tokenizer)

    eligible = [i for i, lengths in enumerate(pair_lengths) if max(lengths) <= MAX_LENGTH]
    splits = split_pairs(records, eligible, seed=args.split_seed)
    print("CVE/exact-code grouped splits: " + json.dumps({k: len(v) for k, v in splits.items()}))
    print("Localization labels: vulnerable changed/deleted lines (proxy, not verified vulnerability lines).")
    print(f"Loading {args.model} model on {device}...")
    model = load_encoder(device, args.model, revision)
    model.eval()
    layers_to_probe = list(range(model.config.num_hidden_layers))

    print(f"Extracting aligned regions with context N={args.context_lines} across {layers_to_probe}...")
    summaries, extractors, stats, retained_indices = extract_all_layers(
        [vul_data[i] for i in splits['train']],
        [ben_data[i] for i in splits['train']], tokenizer, model, layers_to_probe,
        context_lines=args.context_lines,
        pair_lengths=[pair_lengths[i] for i in splits['train']])

    print("Calculating vulnerability directions (d_v) for all layers...")
    layer_directions = {}
    consistency = {'selected_neurons': {}, 'all_neurons': {}}
    all_neuron_directions = {}
    linear_candidates = {'shrinkage_lda': {}, 'logistic': {}, 'rbf_svm': {}}
    train_deltas = {}
    
    for l in layers_to_probe:
        print(f"Layer {l}: building A/B representations...", flush=True)
        down_proj = extractors[l].get_down_projection_weights()
        v_token_means = summaries['vulnerable']['token_mean'][l]
        b_token_means = summaries['patched']['token_mean'][l]
        target_neurons = get_vulnerability_specific_neurons(
            v_token_means, b_token_means, down_proj, k_ratio=0.10)

        # Equal weight per valid line within each side, then equal weight per pair.
        vul_reps = summaries['vulnerable']['line_mean'][l][:, target_neurons] @ down_proj[target_neurons]
        ben_reps = summaries['patched']['line_mean'][l][:, target_neurons] @ down_proj[target_neurons]
        consistency['selected_neurons'][l] = direction_consistency(vul_reps, ben_reps)
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
        all_neurons = torch.arange(down_proj.shape[0], device=down_proj.device)
        all_v = summaries['vulnerable']['line_mean'][l] @ down_proj
        all_p = summaries['patched']['line_mean'][l] @ down_proj
        consistency['all_neurons'][l] = direction_consistency(all_v, all_p)
        all_direction = compute_pairwise_vulnerability_direction(all_v, all_p)
        if torch.norm(all_direction) > 0:
            all_direction = all_direction / torch.norm(all_direction)
        all_neuron_directions[l] = dict(target_neurons=all_neurons, down_proj=down_proj, d_v=all_direction)
        train_deltas[l] = all_v - all_p
        print(f"Layer {l}: fitting E RBF-SVM ({2 * len(all_v)} samples)...", flush=True)
        for parameter, estimator in fit_rbf(all_v, all_p, args.svm_c_values, args.svm_gammas):
            candidates = linear_candidates['rbf_svm']
            candidates[len(candidates)] = dict(layer=l, parameter=parameter, estimator=estimator,
                target_neurons=all_neurons, down_proj=down_proj)
        print(f"Layer {l}: fitting C/D...", flush=True)
        for method, parameter, weight, bias in fit_linear_candidates(
                all_v, all_p, args.lda_shrinkages, args.logistic_c_values, args.split_seed):
            candidates = linear_candidates[method]
            candidates[len(candidates)] = dict(layer=l, parameter=parameter,
                target_neurons=all_neurons, down_proj=down_proj, d_v=weight, bias=bias)
        print(f"Layer {l:2d} | |N_r,l| = {len(target_neurons)}")

    # Keep aggregates, not per-pair arrays, in persisted diagnostics.
    plot_consistency(consistency, run_dir / 'direction_consistency.png')
    for layers in consistency.values():
        for values in layers.values():
            values.pop('delta_norms', None)
            for key in ('cosine_to_mean', 'cosine_to_leave_one_out_mean'):
                values[key].pop('cosines', None)
    with (run_dir / 'direction_consistency.json').open('w') as stream:
        json.dump(dict(scope='train only', layers=consistency), stream, indent=2, allow_nan=False)
    plot_delta_clusters(train_deltas, run_dir / 'delta_clusters.png', args.split_seed)

    # Generate the comprehensive plot
    print("Generating training-only diagnostic plots for all probed layers...")
    plot_all_layers(layer_directions, output_path=run_dir / "projection.png")
    plot_all_layers_pca(layer_directions, output_path=run_dir / "pca.png")

    methods = {'B': all_neuron_directions, 'C': linear_candidates['shrinkage_lda'],
               'D': linear_candidates['logistic'], 'E': linear_candidates['rbf_svm']}
    for width in (1, 2, 4, 8, 16, 'all'):
        methods[f'A_window_{width}'] = {l: dict(info, layer=l, representation='selected',
            window=width, parameter={'window': width}) for l, info in layer_directions.items()}
    csv_rows, selected_methods = [], {}
    counts_report = {}
    for method, candidates in methods.items():
        val = evaluate_localization(records, splits['validation'], tokenizer, model,
            extractors, candidates, description=f'{method} validation')
        best = select_layer(val, candidates)
        # Tune parameters separately within each layer, using validation only.
        by_layer = {}
        for key, info in candidates.items():
            layer = info.get('layer', key)
            if layer not in by_layer or val['layers'][key]['mrr'] > val['layers'][by_layer[layer]]['mrr']:
                by_layer[layer] = key
        chosen = {key: candidates[key] for key in by_layer.values()}
        test = evaluate_localization(records, splits['test'], tokenizer, model,
            extractors, chosen, description=f'{method} test by layer')
        if method == 'E':
            selected_svm = candidates[best]
        selected_methods[method] = dict(layer=candidates[best].get('layer', best),
            parameter=candidates[best].get('parameter'), test=test['layers'][best])
        counts_report[method] = {'validation': val['counts'], 'test': test['counts']}
        for key, info in chosen.items():
            row = dict(method=method, layer=info.get('layer', key),
                parameter=json.dumps(info.get('parameter', {}), sort_keys=True),
                selected_by_validation=key == best,
                validation_pairs=val['counts']['evaluated_pairs'], test_pairs=test['counts']['evaluated_pairs'],
                **{'validation_'+k: v for k, v in val['layers'][key].items()},
                **{'test_'+k: v for k, v in test['layers'][key].items()},
                **{'random_'+k: v for k, v in test['random_baseline'].items()})
            row.update(uncertainty(test['per_pair'], key, records, args.bootstrap, args.split_seed))
            if method == 'E':
                row['score_transform'] = 'tanh(decision_function); ranking uses raw margin to avoid saturation ties'
                row['bounded_score_min'] = test['score_ranges'][key]['min']
                row['bounded_score_max'] = test['score_ranges'][key]['max']
            csv_rows.append(row)
        if method == 'A_window_1':
            selected_layer = candidates[best].get('layer', best)
    write_csv(run_dir / 'report.csv', csv_rows)
    report = dict(model=MODELS[args.model], model_revision=revision,
        split_sizes={k: len(v) for k, v in splits.items()}, train_filtering=stats,
        selected_methods=selected_methods, counts=counts_report,
        results_file='report.csv', label_policy='changed/deleted lines: proxy labels',
        significance='group bootstrap 95% MRR CI; two-sided group sign-flip vs random expectation; Holm within run',
        selection='validation MRR only; per-layer parameter selection; lower layer then smaller grid parameter on ties')
    with (run_dir / 'report.json').open('w') as stream:
        json.dump(report, stream, indent=2)
    print(f'Saved aggregate results to {run_dir / "report.csv"}')

    # Show every layer on a held-out test example; do not combine raw scores.
    test_idx = splits['test'][0]
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
        print("Line | Attention | " + " | ".join(f"L{l}" for l in layers_to_probe)
              + f" | Selected L{selected_layer} | E tanh(margin) | Code")
        print("-" * 100)
        
        inputs, token_to_line, valid_lines, _ = prepare_code_input(
            code_snippet, tokenizer, max_length=MAX_LENGTH)
        inputs = {k: v.to(model.device) for k, v in inputs.items()}
        
        with torch.no_grad():
            for ext in extractors.values(): ext.clear()
            model(**inputs)
            
        num_lines = len(code_snippet.split('\n'))
        lines = code_snippet.split('\n')
        
        # Save line activations before the attention forward overwrites hooks.
        line_acts_by_layer = {
            l: get_line_level_activations(
                extractors[l].activation[0],
                token_to_line, num_lines)
            for l in layers_to_probe
        }
        svm_reps = line_acts_by_layer[selected_svm['layer']] @ selected_svm['down_proj']
        svm_scores = np.tanh(selected_svm['estimator'].decision_function(svm_reps.cpu().numpy()))
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
                
            selected_score = layer_scores[layers_to_probe.index(selected_layer)]
            a_score = a_scores[q].item()
            
            code_line = lines[q]
            if q in changed_lines:
                code_line = f"{color}{code_line}{RESET}"
                
            scores_text = " | ".join(f"{value:7.4f}" for value in layer_scores)
            print(f"Line {q+1:2d} | {a_score:7.4f} | {scores_text} | "
                  f"{selected_score:7.4f} | {svm_scores[q]:7.4f} | {code_line}")
        print("="*100)
    for ext in extractors.values():
        ext.remove_hooks()

if __name__ == "__main__":
    main()
