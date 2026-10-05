"""Frozen-region RBF SVM and train-only delta clustering diagnostics."""
import numpy as np
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC


def fit_rbf(vulnerable, patched, c_values, gammas):
    x = np.concatenate([vulnerable.cpu().numpy(), patched.cpu().numpy()])
    y = np.r_[np.ones(len(vulnerable)), np.zeros(len(patched))]
    for c in sorted(set(c_values)):
        for gamma in sorted(set(gammas)):
            estimator = make_pipeline(StandardScaler(), SVC(C=c, gamma=gamma, kernel='rbf', cache_size=256))
            estimator.fit(x, y)
            yield {'C': c, 'gamma': gamma}, estimator


def plot_delta_clusters(deltas, output, seed):
    from sklearn.cluster import KMeans
    from sklearn.decomposition import PCA
    import matplotlib.pyplot as plt
    count = len(deltas)
    fig, axes = plt.subplots((count + 3) // 4, 4, figsize=(16, 3 * ((count + 3) // 4)), squeeze=False)
    for ax, (layer, delta) in zip(axes.flat, deltas.items()):
        x = delta.detach().cpu().double().numpy()
        norms = np.linalg.norm(x, axis=1)
        x = x[norms > 0] / norms[norms > 0, None]
        # Cap only visualization fitting cost; no subsampling in SVM training.
        if len(x) > 3000:
            x = x[np.random.default_rng(seed).choice(len(x), 3000, replace=False)]
        if len(x) >= 2 and np.any(x != x[0]):
            k = min(3, len(np.unique(x, axis=0)))
            labels = KMeans(n_clusters=k, random_state=seed, n_init=10).fit_predict(x)
            xy = PCA(n_components=2).fit_transform(x)
            ax.scatter(xy[:, 0], xy[:, 1], c=labels, s=5, alpha=.5, cmap='tab10')
        else:
            ax.text(.1, .5, 'Insufficient nonzero distinct deltas')
        ax.set_title(f'Layer {layer}: normalized train deltas')
    for ax in list(axes.flat)[count:]:
        ax.set_visible(False)
    fig.suptitle('Exploratory k-means (up to 3 groups), PCA display; not SVM classes or validated mechanisms')
    fig.tight_layout(rect=(0, 0, 1, .97))
    fig.savefig(output, dpi=160)
    plt.close(fig)
