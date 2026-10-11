"""Attention Distance Eq.4 line-score adaptation on a saved experiment's test split.

Not the full CFG-based fuzzing distance. Requires a fine-tuned CodeBERT checkpoint.
Head mean / incoming-query sum is explicit here: the expired author repository
prevents verification of this reduction against their implementation.
"""
import argparse
import json
from pathlib import Path
import torch
from tqdm import tqdm
from transformers import AutoTokenizer, RobertaConfig, RobertaModel
from core.training_artifacts import load_models, fingerprint
from core.model_config import load_tokenizer, load_encoder, MAX_LENGTH
from core.splits import load_unified_records, split_pairs
from core.mapper import prepare_code_input
from core.evaluation import changed_vulnerable_lines, localization_metrics, evaluate_localization
from core.hook_utils import ActivationExtractor


def line_attention(code, model, tokenizer):
    inputs, mapping, valid, _ = prepare_code_input(code, tokenizer, 512)
    with torch.no_grad():
        output = model(**{k: v.to(model.device) for k, v in inputs.items()}, output_attentions=True)
    # Eq.4 sums layers and tokens. Incoming attention averaged over heads;
    # special query tokens are included, padding is absent, special keys unmapped.
    received = sum(a[0].float().mean(0).sum(0) for a in output.attentions).cpu()
    scores = {q: 0. for q in valid}
    for token, line in mapping.items():
        if line in scores:
            scores[line] += float(received[token])
    return scores


def load_checkpoint(path, base, device):
    config = RobertaConfig.from_pretrained(base)
    config._attn_implementation = 'eager'
    model = RobertaModel(config, add_pooling_layer=False)
    state = torch.load(path, map_location='cpu', weights_only=True)
    state = state.get('state_dict', state)
    normalized = {}
    for key, value in state.items():
        key = key.removeprefix('module.')
        if key.startswith('encoder.roberta.'):
            key = key[len('encoder.roberta.'):]
        elif key.startswith('roberta.'):
            key = key[len('roberta.'):]
        normalized[key] = value
    wanted = model.state_dict()
    missing = set(wanted) - set(normalized)
    if missing:
        raise ValueError(f'Incomplete CodeBERT encoder checkpoint: {sorted(missing)[:5]}')
    model.load_state_dict({k: normalized[k] for k in wanted}, strict=True)
    return model.to(device).eval()


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--dataset', nargs='+', required=True)
    cli.add_argument('--reference-models', required=True, help='Existing inference_models.joblib')
    cli.add_argument('--checkpoint', required=True, help='Trusted fine-tuned LineVul/AD .bin state_dict')
    cli.add_argument('--base-model', default='microsoft/codebert-base')
    cli.add_argument('--compare-method', default='B')
    cli.add_argument('--output-dir', type=Path, required=True)
    args = cli.parse_args()
    if args.output_dir.exists():
        cli.error('Use a new --output-dir')
    for path in [*args.dataset, args.checkpoint, args.reference_models]:
        if not Path(path).is_file():
            cli.error(f'Missing file: {path}')
    reference = load_models(args.reference_models)
    metadata = reference['metadata']
    settings = metadata['training']
    records = [pair for path in args.dataset for pair in load_unified_records(path, settings.get('cwe'))]
    reference_tokenizer, revision = load_tokenizer(settings['model'], metadata['extraction']['revision'])
    eligible = [i for i, pair in enumerate(tqdm(records, desc='Rebuilding reference split'))
                if all(len(reference_tokenizer(side['code'], truncation=False, verbose=False)['input_ids']) <= MAX_LENGTH for side in pair)]
    splits = split_pairs(records, eligible, settings['split_seed'])
    if fingerprint(splits) != metadata['extraction']['splits'] or fingerprint([records[i] for i in splits['train']]) != metadata['extraction']['train_records']:
        raise ValueError('Dataset/order/split does not match saved experiment')
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, use_fast=True)
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = load_checkpoint(args.checkpoint, args.base_model, device)
    common, scores_rows = [], []
    counts = dict(total_test_pairs=len(splits['test']), no_changed_lines=0, no_valid_labels=0, overlength_codebert=0)
    for i in tqdm(splits['test'], desc='Attention line-score adaptation'):
        before, after = (side['code'] for side in records[i])
        labels = changed_vulnerable_lines(before, after)
        if not labels:
            counts['no_changed_lines'] += 1
            continue
        if any(len(tokenizer(code, truncation=False, verbose=False)['input_ids']) > 512 for code in (before, after)):
            counts['overlength_codebert'] += 1
            continue
        scores = line_attention(before, model, tokenizer)
        reference_valid = prepare_code_input(before, reference_tokenizer)[2]
        if set(scores) != reference_valid:
            raise ValueError('Tokenizers disagree on valid lines; do not compare different candidate sets')
        metrics = localization_metrics(scores, labels)
        if metrics is None:
            counts['no_valid_labels'] += 1
            continue
        common.append(i)
        scores_rows.append(metrics)
    if not common:
        raise ValueError('No common fully retained test pairs')
    del model
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    encoder = load_encoder(device, settings['model'], revision)
    info = reference['models'][args.compare_method]
    ext = ActivationExtractor(encoder, info['layer'])
    try:
        comparison = evaluate_localization(records, common, reference_tokenizer, encoder,
            {info['layer']: ext}, {0: info}, description='Matched reference test')
    finally:
        ext.remove_hooks()
    metrics = {k: sum(row[k] for row in scores_rows)/len(scores_rows) for k in scores_rows[0]}
    report = dict(status='paper_equation_adaptation_not_verified_author_reproduction',
        checkpoint=str(Path(args.checkpoint).resolve()), training_overlap='unknown; published checkpoint may overlap BigVul-derived test data',
        attention_reduction='sum layers, mean heads, sum incoming queries, sum line tokens',
        scope='line score only, no CFG physical distance or block clipping', counts=counts,
        common_test_pairs=len(common), full_original_test_comparison=False,
        attention=metrics, comparison_method=args.compare_method, comparison=comparison['layers'][0],
        random=comparison['random_baseline'])
    args.output_dir.mkdir(parents=True)
    (args.output_dir/'report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    import sys
    if "--checkpoint" in sys.argv:
        main()
    else:
        from core.attention_experiment import main as base_main
        base_main()
