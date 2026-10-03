"""Output directories and provenance shared by experiment scripts."""
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from zoneinfo import ZoneInfo


def create_run(script, model, arguments, output_dir=None):
    script = Path(script).resolve()
    started = datetime.now(ZoneInfo('Asia/Taipei'))
    root = Path(output_dir) if output_dir else script.parent / 'outputs'
    directory = root / f'{script.stem}_{model}_{started:%Y%m%d_%H%M%S_%f}'
    directory.mkdir(parents=True, exist_ok=False)

    def git(*args):
        try:
            return subprocess.check_output(
                ['git', '-C', str(script.parent), *args], stderr=subprocess.DEVNULL,
                text=True, timeout=10).strip()
        except (OSError, subprocess.SubprocessError):
            return None

    status = git('status', '--porcelain')
    metadata = {
        'started_at': started.isoformat(), 'timezone': 'Asia/Taipei',
        'script': script.name, 'script_sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
        'git_commit': git('rev-parse', 'HEAD'),
        'git_dirty': None if status is None else bool(status),
        'arguments': json.loads(json.dumps(vars(arguments), default=str)),
        'command': sys.argv, 'working_directory': str(Path.cwd()),
        'output_directory': str(directory.resolve()),
    }
    (directory / 'run.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    print(f'Run output: {directory}', flush=True)
    return directory, metadata
