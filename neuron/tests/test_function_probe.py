import unittest
import torch
import numpy as np
from function_probe import pool_hidden, metrics, confidence_intervals


class ProbeTests(unittest.TestCase):
    def test_pooling_excludes_special_and_padding(self):
        h=torch.tensor([[100.], [2.], [4.], [200.], [300.]])
        pools=pool_hidden(h,torch.tensor([1,1,1,1,0]),torch.tensor([1,0,0,1,1]),
                          torch.tensor([1,4,5,2,0]),1)
        self.assertEqual(pools['cls'].item(),100)
        self.assertEqual(pools['mean'].item(),3)
        self.assertEqual(pools['last'].item(),4)

    def test_metrics_ties_and_group_intervals(self):
        scores=np.array([[2.,-2.], [0.,0.]])
        self.assertEqual(metrics(scores)['pairwise_accuracy'],.75)
        self.assertEqual(metrics(scores)['balanced_accuracy'],.75)
        a=confidence_intervals(scores,[[0],[1]],20,42)
        self.assertEqual(a,confidence_intervals(scores,[[0],[1]],20,42))
        self.assertIsNone(confidence_intervals(scores,[[0,1]],20,42))

