"""Train-only linear directions on paired region representations."""
import numpy as np
import torch
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression


def fit_linear_candidates(vulnerable, patched, shrinkages, c_values, seed=42):
    v = vulnerable.detach().cpu().double().numpy()
    p = patched.detach().cpu().double().numpy()
    x = np.concatenate([v, p])
    y = np.concatenate([np.ones(len(v)), np.zeros(len(p))])
    if not np.isfinite(x).all():
        raise ValueError('Nonfinite training representations')
    candidates = []
    # Pooled within-class covariance (MLE), not covariance of pair differences.
    residuals = np.concatenate([v - v.mean(0), p - p.mean(0)])
    covariance = residuals.T @ residuals / len(x)
    tau = max(float(np.trace(covariance) / x.shape[1]), np.finfo(float).eps)
    delta = v.mean(0) - p.mean(0)
    for shrinkage in sorted(set(shrinkages)):
        regularized = (1 - shrinkage) * covariance + shrinkage * tau * np.eye(x.shape[1])
        w = np.linalg.solve(regularized, delta)
        b = -0.5 * (v.mean(0) + p.mean(0)) @ w
        candidates.append(('shrinkage_lda', shrinkage, w, b))
    scaler = StandardScaler().fit(x)
    for c in sorted(set(c_values)):
        probe = LogisticRegression(C=c, max_iter=3000, random_state=seed).fit(scaler.transform(x), y)
        # Fold train-only scaling into coefficients for direct line scoring.
        w = probe.coef_[0] / scaler.scale_
        b = probe.intercept_[0] - w @ scaler.mean_
        candidates.append(('logistic', c, w, b))
    return [(method, parameter, torch.as_tensor(w, device=vulnerable.device, dtype=vulnerable.dtype), float(b))
            for method, parameter, w, b in candidates]
