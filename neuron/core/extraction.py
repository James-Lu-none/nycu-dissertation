"""Training-only activation aggregation, independent of downstream methods."""
import json
import torch
from tqdm import tqdm
from .model_config import MAX_LENGTH
from .hook_utils import ActivationExtractor
from .mapper import prepare_code_input, aggregate_region_activations
from .regions import get_aligned_regions

def extract_all_layers(vul_data, ben_data, tokenizer, model, layers_to_probe,
                       context_lines=1, max_length=MAX_LENGTH, pair_lengths=None, allow_empty=False):
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
        if not stats['retained'] and not allow_empty:
            raise ValueError("No valid training pairs remain after region filtering")
        for side in summaries.values():
            for kind in side.values():
                for l in layers_to_probe:
                    kind[l] = torch.stack(kind[l]) if kind[l] else torch.empty((0, extractors[l].get_down_projection_weights().shape[0]))
        return summaries, extractors, stats, retained_indices
    except Exception:
        for ext in extractors.values():
            ext.remove_hooks()
        raise

