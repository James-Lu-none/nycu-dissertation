import csv
import tempfile
import unittest
from pathlib import Path
from prepare import convert, METHODS, BENCH

class ExportTests(unittest.TestCase):
    def fixture(self, root):
        (root/'slice_dfg.txt').write_text('2 x.c:1\n4 x.c:2\n6 x.c:3\n')
        rows=[]
        for method in METHODS.values():
            for line,weight,p,status in [(1,2,0,'scored'),(2,4,1,'scored'),(3,6,'','overlength')]:
                rows.append(dict(method=method,requested_file='x.c',line=line,original_dfg_value=weight,function_percentile=p,status=status))
        path=root/'scores.csv'
        with path.open('w') as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
        return path

    def test_weights_and_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);scores=self.fixture(root);convert(root,scores)
            self.assertEqual((root/'linescore/slice_attention.txt').read_text(),'1000 x.c:1\n6000 x.c:2\n6000 x.c:3\n')
            self.assertEqual((root/'slice_dfg.txt').read_text(),'2 x.c:1\n4 x.c:2\n6 x.c:3\n')

    def test_incomplete_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);scores=self.fixture(root)
            scores.write_text(scores.read_text().replace('overlength','not_scored'))
            with self.assertRaises(ValueError):convert(root,scores)
            self.assertFalse((root/'linescore').exists())

    def test_all_builds_preserve_original_commands(self):
        import re
        paths=list(BENCH.glob('*/Dockerfile.linescore'));self.assertEqual(len(paths),41)
        for path in paths:
            original=(path.parent/'Dockerfile').read_text()
            old=re.search(r'^FROM .* AS dd-build\n(.*?)(?=^FROM |\Z)',original,re.M|re.S).group(1)
            commands='ENV DAFL_SELECTIVE_COV='+old.split('ENV DAFL_SELECTIVE_COV=',1)[1]
            commands='\n'.join(l for l in commands.splitlines() if l.strip() and not l.startswith('#'))
            new=path.read_text()
            for stage in ['dafl','attention','rationale']:
                section=new.split(f'AS {stage}-build\n')[1].split('\nFROM ')[0]
                actual='ENV DAFL_SELECTIVE_COV='+section.split('ENV DAFL_SELECTIVE_COV=',1)[1]
                actual='\n'.join(l for l in actual.splitlines() if l.strip() and not l.startswith('#'))
                self.assertEqual(commands,actual,str(path))

if __name__=='__main__':unittest.main()
