"""Flatten layer/parameter fits into a shared CPU worker queue."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from time import perf_counter
from threadpoolctl import threadpool_limits
from tqdm import tqdm

from .linear_directions import fit_linear_candidates
from .nonlinear import fit_rbf


def worker_count(requested):
    if requested < 1:
        raise ValueError('CPU jobs must be positive')
    limits = [requested, len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else (os.cpu_count() or 1)]
    if os.environ.get('SLURM_CPUS_PER_TASK'):
        limits.append(int(os.environ['SLURM_CPUS_PER_TASK']))
    return max(1, min(limits))


def _fit(job, representations, seed, cache_mb):
    layer, method, parameter = job
    v, p = representations[layer]
    start = perf_counter()
    if method == 'rbf_svm':
        c, gamma = parameter
        _, estimator = next(fit_rbf(v, p, [c], [gamma], cache_mb=cache_mb, verbose=False))
        result = dict(parameter={'C': c, 'gamma': gamma}, estimator=estimator)
    else:
        shrinkages = [parameter] if method == 'shrinkage_lda' else []
        c_values = [parameter] if method == 'logistic' else []
        _, _, weight, bias = fit_linear_candidates(v, p, shrinkages, c_values, seed, verbose=False)[0]
        result = dict(parameter=parameter, d_v=weight, bias=bias)
    return layer, method, dict(result, fit_seconds=perf_counter() - start)


def fit_jobs(representations, shrinkages, logistic_cs, svm_cs, gammas,
             jobs=24, seed=42, cache_mb=512):
    """CPU tensors only. Stable candidate ordering regardless of completion order.

    Threads share input arrays; sklearn's native SVM fitting releases the GIL.
    Limit BLAS threads across the pool to avoid jobs * BLAS-thread oversubscription.
    """
    tasks = []
    for layer in sorted(representations):
        tasks.extend((layer, 'shrinkage_lda', x) for x in sorted(set(shrinkages)))
        tasks.extend((layer, 'logistic', x) for x in sorted(set(logistic_cs)))
        tasks.extend((layer, 'rbf_svm', (c, g)) for c in sorted(set(svm_cs)) for g in sorted(set(gammas)))
    workers = min(worker_count(jobs), len(tasks))
    if not tasks:
        return []
    print(f'CPU fits: {len(tasks)} layer/parameter jobs | workers={workers} (requested={jobs}) | SVM cache={cache_mb} MB/job', flush=True)
    results = [None] * len(tasks)
    with threadpool_limits(limits=1), ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_fit, task, representations, seed, cache_mb): i for i, task in enumerate(tasks)}
        with tqdm(total=len(tasks), desc='Fitting C/D/E', unit='job') as progress:
            for future in as_completed(futures):
                index = futures[future]
                results[index] = future.result()
                layer, method, info = results[index]
                tqdm.write(f'Fit done layer={layer} method={method} parameter={info["parameter"]} seconds={info["fit_seconds"]:.1f}')
                progress.update(1)
    return results
