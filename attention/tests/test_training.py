import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import unittest
import torch
from transformers import ModernBertConfig, ModernBertModel, RobertaConfig, RobertaModel
from model import Classifier, line_distribution, rationale_loss, ATTENTION_BACKEND


class TrainingTests(unittest.TestCase):
    def compare(self,config,cls):
        config._attn_implementation=ATTENTION_BACKEND
        config.reference_compile=False
        torch.manual_seed(42)
        net=Classifier(cls(config)).eval()
        inputs={'input_ids':torch.tensor([[0,5,6,7,2,1],[0,8,9,2,1,1]]),
                'attention_mask':torch.tensor([[1,1,1,1,1,0],[1,1,1,1,0,0]])}
        logits,attention=net(inputs)
        self.assertEqual(attention.shape,(2,6))
        torch.testing.assert_close(attention.sum(-1),torch.ones(2))
        self.assertEqual(attention[0,-1].item(),0.)
        config._attn_implementation='eager'
        baseline=cls(config).eval();baseline.load_state_dict(net.encoder.state_dict())
        expected=baseline(**inputs,output_attentions=True)
        torch.testing.assert_close(attention,expected.attentions[net.attention_layer][:,:,0].mean(1),atol=1e-5,rtol=1e-4)
        torch.testing.assert_close(logits,net.head(expected.last_hidden_state[:,0]),atol=1e-5,rtol=1e-4)
        config._attn_implementation=ATTENTION_BACKEND
        config.reference_compile=False
        net.train()
        _,attention=net(inputs)
        rows=[dict(label=1,line_ids=[-1,0,0,1,-1,-1],positive=[1],random=[0]),
              dict(label=0,line_ids=[-1,0,1,-1,-1,-1],positive=[],random=[])]
        rationale_loss(attention,rows,'rationale').backward()
        module=net.attention_module
        grad=module.Wqkv.weight.grad if hasattr(module,'Wqkv') else module.query.weight.grad
        self.assertGreater(grad.abs().sum().item(),0.)

    def test_roberta_attention_and_gradient(self):
        self.compare(RobertaConfig(vocab_size=32,hidden_size=16,num_attention_heads=2,num_hidden_layers=2,
                                  intermediate_size=32,max_position_embeddings=32,attention_probs_dropout_prob=0.,hidden_dropout_prob=0.),RobertaModel)

    def test_modernbert_global_attention_and_gradient(self):
        self.compare(ModernBertConfig(vocab_size=32,hidden_size=16,num_attention_heads=2,num_hidden_layers=3,
                                     intermediate_size=32,max_position_embeddings=32,global_attn_every_n_layers=2,
                                     local_attention=4,attention_dropout=0.,pad_token_id=1,bos_token_id=0,eos_token_id=2,cls_token_id=0,sep_token_id=2),ModernBertModel)

    def test_equal_line_mean_and_weak_label_skip(self):
        x=torch.tensor([[.1,.2,.2,.4,.1]],requires_grad=True)
        ids=torch.tensor([-1,0,0,1,-1])
        torch.testing.assert_close(line_distribution(x[0],ids),torch.tensor([1/3,2/3]))
        rows=[dict(label=0,line_ids=ids.tolist(),positive=[1],random=[0])]
        loss=rationale_loss(x,rows,'rationale')
        self.assertEqual(loss.item(),0.);loss.backward()
        self.assertEqual(x.grad.abs().sum().item(),0.)


if __name__=='__main__': unittest.main()
