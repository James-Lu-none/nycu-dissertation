"""One independent experiment per GPU; reuse each slot as soon as it finishes."""
import argparse
import csv
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def gpu_slots(explicit=None):
    visible = os.environ.get('CUDA_VISIBLE_DEVICES')
    values = explicit if explicit is not None else (visible if visible is not None else '0,1')
    slots = [s.strip() for s in values.split(',') if s.strip()]
    if not slots or '-1' in slots or len(set(slots)) != len(slots):
        raise ValueError('GPU IDs must be nonempty and unique')
    if explicit is None:
        slots = slots[:2]
    elif visible is not None and not set(slots) <= set(visible.split(',')):
        raise ValueError('GPU IDs must be identifiers from the inherited CUDA_VISIBLE_DEVICES allocation')
    return slots


def schedule(jobs, slots, root):
    """jobs: (name, argv). Keep logs separate; fail without launching further jobs."""
    pending = list(jobs)
    active = {}
    records = []
    failed = False

    def write_status():
        with (root/'jobs.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=['experiment','gpu','pid','status','exit_code','seconds'])
            writer.writeheader(); writer.writerows(records)

    try:
        while pending or active:
            for gpu in slots:
                if failed or not pending or gpu in active:
                    continue
                name, command = pending.pop(0)
                log = (root/f'{name}.log').open('w')
                env = dict(os.environ, CUDA_VISIBLE_DEVICES=gpu, ATTENTION_REQUIRE_CUDA='1')
                try:
                    process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT,
                                               start_new_session=True)
                except BaseException:
                    log.close()
                    raise
                row = dict(experiment=name,gpu=gpu,pid=process.pid,status='running',exit_code='',seconds='')
                records.append(row)
                active[gpu] = (process, log, row, time.monotonic())
                print(f'Start {name} | GPU {gpu} | log: {log.name}', flush=True)
                write_status()
            for gpu, (process, log, row, started) in list(active.items()):
                code = process.poll()
                if code is None:
                    continue
                log.close()
                row.update(status='completed' if code == 0 else 'failed',exit_code=code,
                           seconds=round(time.monotonic()-started,2))
                del active[gpu]
                failed |= code != 0
                print(f'{row["status"]}: {row["experiment"]} | GPU {gpu} | exit={code}', flush=True)
                write_status()
            if failed and not active:
                break
            if active:
                time.sleep(.2)
    finally:
        # Also stop training children on Ctrl-C / scheduler termination.
        for process, log, row, started in active.values():
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        for process, log, row, started in active.values():
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL); process.wait()
            log.close()
            row.update(status='interrupted',exit_code=process.returncode,seconds=round(time.monotonic()-started,2))
        records.extend(dict(experiment=name,gpu='',pid='',status='not_started',exit_code='',seconds='')
                       for name,_ in pending)
        write_status()
    return not failed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--models', nargs='+', required=True)
    parser.add_argument('--modes', nargs='+', required=True)
    parser.add_argument('--gpus', help='Comma-separated device IDs or UUIDs; defaults to first two allocated GPUs')
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--max-length', type=int)
    args, training_args = parser.parse_known_args()
    slots = gpu_slots(args.gpus)
    root = args.output_root
    root.mkdir(parents=True, exist_ok=True)
    jobs=[]
    for model in args.models:
        for mode in args.modes:
            name=f'{model}_{mode}'
            if (root/name).exists() or (root/f'{name}.log').exists():
                raise ValueError(f'Output already exists: {name}; choose a fresh OUTPUT_DIR')
            limit=args.max_length or (512 if model=='codebert' else 8192)
            jobs.append((name,[sys.executable,'-u',str(Path(__file__).with_name('train.py')),
                              '--model',model,'--mode',mode,'--max-length',str(limit),
                              '--output-dir',str(root/name),*training_args]))
    if len({name for name,_ in jobs}) != len(jobs):
        raise ValueError('Duplicate model/mode experiments')
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    print(f'GPU slots: {slots}; queued experiments: {len(jobs)}',flush=True)
    if not schedule(jobs, slots, root):
        raise SystemExit('Experiment failed. Remaining queued jobs were not started; see jobs.csv and logs.')
    subprocess.run([sys.executable,str(Path(__file__).with_name('summarize.py')),str(root)],check=True)


if __name__=='__main__': main()
