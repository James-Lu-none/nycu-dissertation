import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from get_dataset_hf_bigvul import convert_row, export_rows


class BigVulExportTests(unittest.TestCase):
    def test_pair_metadata_and_filters(self):
        row = dict(lang='C', func_before='int f(){return 0;}', func_after='int f(){return 1;}',
                   **{'CVE ID': 'CVE-test', 'CWE ID': 'CWE-20', 'commit_message': 'fix'})
        pair, reason = convert_row(row, 0, 'sha', 'train')
        self.assertEqual(reason, 'exported_pairs')
        self.assertEqual(pair['metadata']['CWE ID'], 'CWE-20')
        self.assertEqual(pair['metadata']['commit_message'], 'fix')
        self.assertEqual(pair['func_before'], row['func_before'])
        self.assertEqual(pair, convert_row(row, 0, 'sha', 'train')[0])
        rows = [row, dict(row, lang='C++'), dict(row, func_after=None),
                dict(row, func_after=row['func_before'])]
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            output = Path(tmp) / 'bigvul.jsonl'
            report = export_rows(rows, output, 'sha', 'train')
            self.assertEqual(report['counts']['exported_pairs'], 1)
            self.assertEqual(json.loads(output.read_text()), pair)
            with self.assertRaises(FileExistsError):
                export_rows(rows, output, 'sha', 'train')
