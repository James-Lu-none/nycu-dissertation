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

def run_umap(nc):
    u = umap.UMAP(n_components=nc, n_neighbors=50, min_dist=0.0, random_state=42)
    return u.fit_transform(X)

print("\n--- Test 1: Run 16D then 10D (Original Pipeline A -> Pipeline B) ---")
np.random.seed(42) # reset global seed just in case
X16 = run_umap(16)
X10_test1 = run_umap(10)
hdb = HDBSCAN(min_cluster_size=200, min_samples=30, metric='euclidean')
lbls = hdb.fit_predict(X10_test1)
mask = lbls != -1
score = silhouette_score(X10_test1[mask], lbls[mask], random_state=42)
print(f"Test 1 Score (10D): {score:.4f}, Clusters: {len(np.unique(lbls[mask]))}, Core Points: {np.sum(mask)}")

print("\n--- Test 2: Run 10D directly ---")
np.random.seed(42)
X10_test2 = run_umap(10)
hdb2 = HDBSCAN(min_cluster_size=200, min_samples=30, metric='euclidean')
lbls2 = hdb2.fit_predict(X10_test2)
mask2 = lbls2 != -1
score2 = silhouette_score(X10_test2[mask2], lbls2[mask2], random_state=42)
print(f"Test 2 Score (10D): {score2:.4f}, Clusters: {len(np.unique(lbls2[mask2]))}, Core Points: {np.sum(mask2)}")
