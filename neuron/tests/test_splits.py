import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.splits import split_pairs


class SplitTests(unittest.TestCase):
    def test_group_integrity_and_determinism(self):
        pairs = [({'id': str(i), 'code': f'v{i}'}, {'id': str(i), 'code': f'p{i}'})
                 for i in range(20)]
        pairs[1][0]['id'] = pairs[0][0]['id']
        pairs[1][1]['id'] = pairs[0][1]['id']
        pairs[2][0]['code'] = pairs[1][1]['code']
        splits = split_pairs(pairs, range(20))
        self.assertEqual(splits, split_pairs(pairs, range(20)))
        flat = [i for part in splits.values() for i in part]
        self.assertEqual(sorted(flat), list(range(20)))
        self.assertEqual(len(flat), len(set(flat)))
        owner = {i: name for name, part in splits.items() for i in part}
        self.assertEqual(owner[0], owner[1])
        self.assertEqual(owner[1], owner[2])

    def test_eligibility_and_small_dataset(self):
        pairs = [({'id': '', 'code': f'v{i}'}, {'id': '', 'code': f'p{i}'})
                 for i in range(4)]
        splits = split_pairs(pairs, [1, 2, 3])
        self.assertEqual(sorted(i for part in splits.values() for i in part), [1, 2, 3])
        self.assertTrue(all(splits.values()))
        with self.assertRaises(ValueError):
            split_pairs(pairs, [0, 1])
