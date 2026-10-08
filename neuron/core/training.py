"""Fit A–E using cached all-neuron region summaries only."""
import torch
from .attribution import get_vulnerability_specific_neurons
from .direction import compute_pairwise_vulnerability_direction, score_target_line
from .direction_consistency import direction_consistency
from .fit_jobs import fit_jobs


def train_methods(summaries, projections, args):
    layers_to_probe = sorted(projections)
    print("Calculating vulnerability directions (d_v) for all layers...")
    layer_directions = {}
    consistency = {'selected_neurons': {}, 'all_neurons': {}}
    all_neuron_directions = {}
    linear_candidates = {'shrinkage_lda': {}, 'logistic': {}, 'rbf_svm': {}}
    fit_representations = {}

    for l in layers_to_probe:
        print(f"Layer {l}: building A/B representations...", flush=True)
        down_proj = projections[l]
        v_token_means = summaries['vulnerable']['token_mean'][l]
        b_token_means = summaries['patched']['token_mean'][l]
        target_neurons = get_vulnerability_specific_neurons(
            v_token_means, b_token_means, down_proj, k_ratio=args.top_k_ratio)

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
        fit_representations[l] = (all_v.detach().cpu(), all_p.detach().cpu())
        print(f"Layer {l:2d} | |N_r,l| = {len(target_neurons)}")

    for layer, method, fitted in fit_jobs(
            fit_representations, args.lda_shrinkages, args.logistic_c_values,
            args.svm_c_values, args.svm_gammas, jobs=args.cpu_jobs,
            seed=args.split_seed, cache_mb=args.svm_cache_mb):
        base = all_neuron_directions[layer]
        if 'd_v' in fitted:
            fitted['d_v'] = fitted['d_v'].to(base['down_proj'])
        candidates = linear_candidates[method]
        candidates[len(candidates)] = dict(layer=layer, target_neurons=base['target_neurons'],
                                         down_proj=base['down_proj'], **fitted)
    del fit_representations

    methods = {'B': all_neuron_directions, 'C': linear_candidates['shrinkage_lda'],
               'D': linear_candidates['logistic'], 'E': linear_candidates['rbf_svm']}
    for width in (1, 2, 4, 8, 16, 'all'):
        methods[f'A_window_{width}'] = {l: dict(info, layer=l, representation='selected',
            window=width, parameter={'window': width}) for l, info in layer_directions.items()}
    return methods, layer_directions, consistency
