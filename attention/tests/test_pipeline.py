"""Offline end-to-end test with a tiny locally generated encoder and tokenizer."""
import contextlib
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tokenizers import Tokenizer
from tokenizers.models import WordLevel
from tokenizers.pre_tokenizers import Whitespace
from tokenizers.processors import TemplateProcessing
from transformers import PreTrainedTokenizerFast, RobertaConfig, RobertaModel
import train


class PipelineTest(unittest.TestCase):
    def test_three_arms_write_reports_checkpoints_and_plots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); model_path=root/'encoder'
            tok=Tokenizer(WordLevel({'[UNK]':0,'[PAD]':1,'[CLS]':2,'[SEP]':3,'int':4,'return':5},unk_token='[UNK]'))
            tok.pre_tokenizer=Whitespace()
            tok.post_processor=TemplateProcessing(single='[CLS] $A [SEP]',special_tokens=[('[CLS]',2),('[SEP]',3)])
            tokenizer=PreTrainedTokenizerFast(tokenizer_object=tok,unk_token='[UNK]',pad_token='[PAD]',cls_token='[CLS]',sep_token='[SEP]')
            tokenizer.save_pretrained(model_path)
            RobertaModel(RobertaConfig(vocab_size=6,hidden_size=16,num_hidden_layers=1,num_attention_heads=2,
                                      intermediate_size=24,max_position_embeddings=66,pad_token_id=1)).save_pretrained(model_path)
            dataset=root/'dataset.jsonl'
            with dataset.open('w') as f:
                for i in range(30):
                    f.write(json.dumps(dict(pair_id=str(i),func_before=f'int f{i}() {{\nreturn 0;\n}}',
                                            func_after=f'int f{i}() {{\nreturn 1;\n}}',metadata={}))+'\n')
            with patch.dict(train.MODELS,{'tiny':str(model_path)}):
                for mode in ('classification','rationale','random'):
                    dest=root/mode
                    argv=['train.py','--model','tiny','--mode',mode,'--dataset',str(dataset),
                          '--output-dir',str(dest),'--epochs','1','--batch-size','2','--accumulation','3',
                          '--cpu-threads','1','--max-length','32']
                    with patch.object(sys,'argv',argv),contextlib.redirect_stdout(io.StringIO()): train.main()
                    self.assertTrue((dest/'complete.json').exists())
                    self.assertTrue((dest/'best.pt').exists())
                    self.assertTrue((dest/'training.png').exists())
                    self.assertTrue((dest/'test/line_scores.png').exists())
                    with (dest/'report.csv').open() as f: rows=list(csv.DictReader(f))
                    self.assertEqual(len(rows),4)
                    self.assertTrue(rows[-1]['auroc'])
                    if mode!='classification':
                        self.assertGreater(json.loads((dest/'run.json').read_text())['loss_balance'],0)


if __name__=='__main__': unittest.main()
