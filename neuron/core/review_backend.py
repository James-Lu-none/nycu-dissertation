"""vLLM batch inference and audit logging."""
import contextlib
import difflib
import json
import os
import sys

from .review_rules import SCHEMA, messages_for, finalize_verdict

@contextlib.contextmanager
def backend_log(path):
    """Capture Python and native backend output, including worker startup logs."""
    with open(path, 'a', buffering=1) as log:
        saved = [os.dup(fd) for fd in (1, 2)]
        try:
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(log.fileno(), 1)
            os.dup2(log.fileno(), 2)
            with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
                yield
        finally:
            log.flush()
            for fd, original in zip((1, 2), saved):
                os.dup2(original, fd)
                os.close(original)


def write_analysis(stream, row):
    stream.write(f"\n{'=' * 72}\nPair {row['pair_index']} | {row['decision']} | {row.get('timestamp', '')}\n")
    stream.write(f"Pair hash: {row.get('pair_hash')}\nModel revision: {row.get('model_revision')}\n")
    pair = row.get('input', {})
    stream.write('METADATA\n' + json.dumps(pair.get('metadata', {}), indent=2, ensure_ascii=False) + '\n')
    for side in ('before', 'after'):
        stream.write(side.upper() + '\n')
        for line_no, line in enumerate(pair.get(side, '').splitlines(), 1):
            stream.write(f'{line_no:5d} | {line}\n')
    stream.write('DIFF\n' + '\n'.join(difflib.unified_diff(
        pair.get('before', '').splitlines(), pair.get('after', '').splitlines(),
        fromfile='before', tofile='after', lineterm='')) + '\n')
    for label, value in (
            ('DETERMINISTIC CHECKS', row.get('deterministic_checks')),
            ('MODEL CHECKS', row.get('checks')),
            ('REASON CODES', row.get('reason_codes')),
            ('OBSERVED EVIDENCE', row.get('evidence')),
            ('HYPOTHESES', row.get('hypotheses')),
            ('CAUSAL CHAIN', row.get('causal_chain')),
            ('CODE ASSESSMENT', row.get('code_assessment')),
            ('PROVENANCE', row.get('provenance_assessment')),
            ('MISSING EVIDENCE', row.get('missing_evidence')),
            ('EXPERIMENT ELIGIBILITY', row.get('deterministic_checks', {}).get('experiment_eligibility'))):
        stream.write(label + '\n' + json.dumps(value, indent=2, ensure_ascii=False) + '\n')
    stream.write(f"Needs external context: {row.get('needs_external_context', 'not evaluated')}\n")
    stream.write(f"Finish reason: {row.get('finish_reason', 'not generated')}\n")
    stream.write('RAW MODEL RESPONSE\n' + row.get('raw_response', '(LLM not run)') + '\n')
    stream.flush()


class VLLMReviewer:
    def __init__(self, args):
        from transformers import AutoConfig
        from vllm import LLM, SamplingParams
        from vllm.sampling_params import StructuredOutputsParams
        self.args = args
        config = AutoConfig.from_pretrained(args.model, revision=args.revision)
        self.resolved_revision = getattr(config, '_commit_hash', None)
        self.engine = LLM(
            model=args.model, revision=self.resolved_revision or args.revision,
            dtype='bfloat16', tensor_parallel_size=args.tensor_parallel_size,
            gpu_memory_utilization=args.gpu_memory_utilization,
            max_model_len=args.max_input_tokens + args.max_new_tokens,
            max_num_seqs=args.batch_size, seed=args.seed, disable_log_stats=True)
        self.tokenizer = self.engine.get_tokenizer()
        self.sampling = SamplingParams(
            temperature=0, seed=args.seed, max_tokens=args.max_new_tokens,
            structured_outputs=StructuredOutputsParams(json=SCHEMA))

    def review_batch(self, items):
        results = [None] * len(items)
        prompts, positions = [], []
        for i, (pair, checks) in enumerate(items):
            ids = self.tokenizer.apply_chat_template(
                messages_for(pair, checks), tokenize=True, add_generation_prompt=True)
            if len(ids) > self.args.max_input_tokens:
                results[i] = {'decision': 'review', 'reason_codes': ['review_context_overflow'],
                              'input_tokens': len(ids)}
            else:
                prompts.append({'prompt_token_ids': ids})
                positions.append(i)
        if prompts:
            outputs = self.engine.generate(prompts, self.sampling, use_tqdm=False)
            if len(outputs) != len(positions):
                raise RuntimeError('vLLM returned an unexpected number of responses')
            for i, output in zip(positions, outputs):
                completion = output.outputs[0]
                results[i] = finalize_verdict(completion.text, *items[i], completion.finish_reason)
        return results


