"""Frozen-region RBF SVM."""
import numpy as np
from time import perf_counter
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC


def fit_rbf(vulnerable, patched, c_values, gammas, cache_mb=256, verbose=True):
    x = np.concatenate([vulnerable.cpu().numpy(), patched.cpu().numpy()])
    y = np.r_[np.ones(len(vulnerable)), np.zeros(len(patched))]
    for c in sorted(set(c_values)):
        for gamma in sorted(set(gammas)):
            estimator = make_pipeline(StandardScaler(), SVC(C=c, gamma=gamma, kernel='rbf', cache_size=cache_mb))
            if verbose: print(f"RBF fit start C={c} gamma={gamma} samples={len(x)} features={x.shape[1]}", flush=True)
            started = perf_counter()
            estimator.fit(x, y)
            if verbose: print(f"RBF fit done C={c} gamma={gamma} seconds={perf_counter()-started:.1f} support_vectors={len(estimator[-1].support_)}", flush=True)
            yield {'C': c, 'gamma': gamma}, estimator
