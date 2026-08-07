import numpy as np
import os
import umap
from sklearn.cluster import HDBSCAN
from sklearn.metrics import silhouette_score
import warnings
warnings.filterwarnings('ignore')

models_dir = '/home/khyehlab/314581029/nycu-dissertation/models'
cache_file = os.path.join(models_dir, 'raw_embeddings.npy')

X = np.load(cache_file)[:5000]
print("Loaded X:", X.shape)

def eval_clustering(nc, nn, mcs, metric_u, init, rs):
    try:
        u = umap.UMAP(n_components=nc, n_neighbors=nn, min_dist=0.0, metric=metric_u, random_state=rs, init=init)
        X_emb = u.fit_transform(X)
        h = HDBSCAN(min_cluster_size=mcs, min_samples=30, metric='euclidean')
        lbls = h.fit_predict(X_emb)
        mask = lbls != -1
        if np.sum(mask) > 1 and len(np.unique(lbls[mask])) > 1:
            score = silhouette_score(X_emb[mask], lbls[mask], random_state=42)
            return score, len(np.unique(lbls[mask])), np.sum(mask)
        return -1, 0, 0
    except Exception as e:
        return -1, 0, 0

print("Testing permutations...")
configs = [
    (10, 50, 200, 'euclidean', 'pca', 42),
    (10, 50, 200, 'euclidean', 'random', 42),
    (10, 50, 200, 'euclidean', 'random', 0),
    (10, 50, 200, 'euclidean', 'random', 100),
    (10, 50, 200, 'cosine', 'pca', 42),
    (10, 50, 200, 'cosine', 'random', 42),
    (10, 15, 200, 'euclidean', 'pca', 42),
    (10, 15, 200, 'cosine', 'pca', 42),
]

for nc, nn, mcs, mu, init, rs in configs:
    s, c, cp = eval_clustering(nc, nn, mcs, mu, init, rs)
    print(f"nc={nc}, nn={nn}, mcs={mcs}, u_metric={mu}, init={init}, rs={rs} -> Score: {s:.4f}, Clusters: {c}, Core: {cp}")
