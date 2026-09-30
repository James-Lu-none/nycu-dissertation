import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import review_dataset as audit

class AuditTests(unittest.TestCase):
    def verdict(self):
        return dict(decision='keep', reason_codes=['supported'], evidence=['before line 1'],
                    needs_external_context=False, hypotheses=[], missing_evidence=[],
                    checks={k: 'pass' for k in ('same_function','complete_c','security_relevance','fix_plausible','metadata_consistent')})

    def test_strict_verdict_and_uncertainty(self):
        v=self.verdict()
        self.assertEqual(audit.parse_verdict(json.dumps(v))['decision'],'keep')
        v['checks']['security_relevance']='unknown'
        self.assertEqual(audit.parse_verdict(json.dumps(v))['decision'],'review')
        with self.assertRaises(ValueError): audit.parse_verdict('{"decision":"keep"}')
        with self.assertRaises(ValueError): audit.parse_verdict('not json')

    def test_missing_evidence_and_metadata_guard(self):
        v = self.verdict()
        v['missing_evidence'] = ['callee implementation']
        self.assertEqual(audit.parse_verdict(json.dumps(v))['decision'], 'review')
        v = self.verdict()
        result = audit.finalize_verdict(json.dumps(v), {'metadata': {'id': 'CVE-1'}},
                                        {'syntax': {}}, 'stop')
        self.assertEqual(result['decision'], 'review')
        self.assertEqual(result['checks']['metadata_consistent'], 'unknown')
        self.assertTrue(result['needs_external_context'])

    def test_metadata(self):
        self.assertFalse(audit.metadata_complete({'id':'CVE-1'}))
        self.assertTrue(audit.metadata_complete({'before':{'CVE Description':'desc','commit_message':'fix'}}))

    def test_checks_and_resume(self):
        def tokenizer(code, **kwargs): return {'input_ids':list(range(len(code)+2))}
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'pairs.jsonl';out=Path(tmp)/'audit.jsonl'
            pair={'func_before':'int f(){return 1;}','func_after':'int f(){return 2;}'}
            src.write_text('\n'.join(json.dumps(x) for x in [pair,pair]))
            argv=['review_dataset.py','--input',str(src),'--output',str(out),'--checks-only']
            with patch('sys.argv',argv), patch.dict(sys.modules, {'transformers': SimpleNamespace(AutoTokenizer=SimpleNamespace(from_pretrained=lambda *a, **k: tokenizer))}), patch.object(audit,'make_parser',return_value=None),contextlib.redirect_stdout(io.StringIO()):
                audit.main();first=out.read_text();audit.main()
            self.assertEqual(first,out.read_text())
            rows=[json.loads(x) for x in first.splitlines()]
            self.assertEqual(rows[0]['decision'],'review')
            self.assertEqual(rows[1]['reason_codes'],['duplicate_pair'])
            src.write_text(json.dumps(dict(pair,func_after='changed')))
            with patch('sys.argv',argv),patch.object(audit,'make_parser',return_value=None):
                with self.assertRaisesRegex(ValueError,'another dataset'): audit.main()

    def test_length_and_syntax_do_not_fake_safety(self):
        pair={'before':'abc','after':'defgh'}
        checks=audit.inspect_pair(pair,lambda s,**kw:{'input_ids':list(s)},None,4)
        self.assertEqual(checks['reject_reasons'], [])
        self.assertFalse(checks['experiment_eligibility']['eligible'])
        self.assertEqual(checks['syntax']['before']['status'],'unavailable')

class BatchAuditTests(unittest.TestCase):
    def test_batched_calls_logs_and_resume(self):
        def tokenizer(code, **kwargs): return {'input_ids': list(range(len(code)+2))}
        calls=[]
        class FakeReviewer:
            resolved_revision='test-revision'
            def __init__(self,args): pass
            def review_batch(self,items):
                calls.append(len(items))
                return [{'decision':'review','reason_codes':['uncertain'],
                         'raw_response':'model explanation'} for _ in items]
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'pairs.jsonl';out=Path(tmp)/'audit.jsonl'
            src.write_text('\n'.join(json.dumps({'func_before':f'int f{i}(){{return 1;}}',
                                                  'func_after':f'int f{i}(){{return 2;}}'}) for i in range(5)))
            argv=['audit','--input',str(src),'--output',str(out),'--batch-size','2']
            with patch('sys.argv',argv),patch.dict(sys.modules, {'transformers': SimpleNamespace(AutoTokenizer=SimpleNamespace(from_pretrained=lambda *a, **k: tokenizer))}),patch.object(audit,'make_parser',return_value=None),patch.object(audit,'VLLMReviewer',FakeReviewer),contextlib.redirect_stdout(io.StringIO()):
                audit.main()
                audit.main()
            self.assertEqual(calls,[2,2,1])
            rows=[json.loads(x) for x in out.read_text().splitlines()]
            self.assertEqual([r['pair_index'] for r in rows],list(range(5)))
            self.assertIn('model_request',rows[0])
            log=Path(str(out)+'.analysis.log').read_text()
            self.assertEqual(log.count('Pair 0 |'),1)
            self.assertIn('model explanation',log)
            self.assertIn('int f0()',log)

    def test_vllm_context_and_output_alignment(self):
        from types import SimpleNamespace
        reviewer=audit.VLLMReviewer.__new__(audit.VLLMReviewer)
        reviewer.args=SimpleNamespace(max_input_tokens=3)
        reviewer.sampling=object()
        class Tokenizer:
            def apply_chat_template(self,messages,**kwargs):
                return [1]* (4 if 'long-code' in messages[1]['content'] else 2)
        reviewer.tokenizer=Tokenizer()
        raw=json.dumps(AuditTests().verdict())
        class Engine:
            def generate(self,prompts,params,**kwargs):
                self.prompts=prompts
                return [SimpleNamespace(outputs=[SimpleNamespace(text=raw,finish_reason='stop')])]
        reviewer.engine=Engine()
        checks={'syntax':{side:{'status':'pass'} for side in ('before','after')}}
        pair={'before':'a','after':'b','metadata':{'description':'d','commit_message':'m'}}
        results=reviewer.review_batch([(dict(pair,before='long-code'),checks),(pair,checks)])
        self.assertEqual(results[0]['reason_codes'],['review_context_overflow'])
        self.assertEqual(results[1]['decision'],'keep')
        self.assertEqual(len(reviewer.engine.prompts),1)
        truncated=audit.finalize_verdict(raw,pair,checks,'length')
        self.assertEqual(truncated['decision'],'review')

    def test_interrupted_batch_can_resume(self):
        def tokenizer(code,**kwargs): return {'input_ids': [1,2,3]}
        class Broken:
            resolved_revision='r'
            def __init__(self,args): pass
            def review_batch(self,items): raise RuntimeError('fake OOM')
        class Working(Broken):
            def review_batch(self,items):
                return [{'decision':'review','reason_codes':['uncertain']} for _ in items]
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'pairs.jsonl';out=Path(tmp)/'audit.jsonl'
            src.write_text(json.dumps({'func_before':'a','func_after':'b'}))
            argv=['audit','--input',str(src),'--output',str(out)]
            with patch('sys.argv',argv),patch.dict(sys.modules, {'transformers': SimpleNamespace(AutoTokenizer=SimpleNamespace(from_pretrained=lambda *a, **k: tokenizer))}),patch.object(audit,'make_parser',return_value=None),contextlib.redirect_stdout(io.StringIO()):
                with patch.object(audit,'VLLMReviewer',Broken),self.assertRaisesRegex(RuntimeError,'fake OOM'):
                    audit.main()
                self.assertEqual(out.read_text(),'')
                self.assertIn('fake OOM',Path(str(out)+'.runtime.log').read_text())
                with patch.object(audit,'VLLMReviewer',Working): audit.main()
            self.assertEqual(len(out.read_text().splitlines()),1)
