import joblib
import os
import matplotlib.pyplot as plt
import umap
import numpy as np
from sklearn.metrics import silhouette_score

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(script_dir)
    models_dir = os.path.join(root_dir, 'models')
    output_dir = os.path.join(root_dir, 'visualizations')
    os.makedirs(output_dir, exist_ok=True)
    
    print("Loading models...")
    umap_kmeans = joblib.load(os.path.join(models_dir, 'umap_kmeans.pkl'))
    kmeans = joblib.load(os.path.join(models_dir, 'kmeans.pkl'))
    
    umap_hdbscan = joblib.load(os.path.join(models_dir, 'umap_hdbscan.pkl'))
    hdbscan = joblib.load(os.path.join(models_dir, 'hdbscan.pkl'))
    
    # KMEANS
    print("Processing KMeans visualization...")
    X_kmeans_16d = getattr(umap_kmeans, 'embedding_', None)
    labels_kmeans = kmeans.labels_
    
    unique_k, counts_k = np.unique(labels_kmeans, return_counts=True)
    count_dict_k = dict(zip(unique_k, counts_k))
    
    if X_kmeans_16d is not None:
        if X_kmeans_16d.shape[0] > 10000:
            print("Subsampling KMeans data to 10,000 points for faster visualization...")
            np.random.seed(42) # Ensure consistent sampling
            idx = np.random.choice(X_kmeans_16d.shape[0], 10000, replace=False)
            X_kmeans_16d = X_kmeans_16d[idx]
            labels_kmeans = labels_kmeans[idx]
            
        print(f"Projecting KMeans 16D to 2D (size: {X_kmeans_16d.shape})...")
        reducer_2d = umap.UMAP(n_components=2, n_neighbors=50, min_dist=0.0, n_jobs=-1, verbose=True)
        X_kmeans_2d = reducer_2d.fit_transform(X_kmeans_16d)
        
        plt.figure(figsize=(12, 10))
        scatter = plt.scatter(X_kmeans_2d[:, 0], X_kmeans_2d[:, 1], c=labels_kmeans, cmap='tab20', s=2, alpha=0.6)
        score = silhouette_score(X_kmeans_16d, labels_kmeans, random_state=42) if X_kmeans_16d.shape[0] > 1 else 0
        plt.title(f'Global KMeans Clusters (41 Benchmarks)\nUMAP(n_neighbors={umap_kmeans.n_neighbors}, min_dist={umap_kmeans.min_dist}) | Silhouette: {score:.4f}')
        cbar = plt.colorbar(scatter, label='Cluster ID (Point Count)')
        unique_ids_k = sorted([k for k in count_dict_k.keys()])
        cbar.set_ticks(unique_ids_k)
        cbar.ax.tick_params(labelsize=8)
        cbar.set_ticklabels([f"{k} ({count_dict_k[k]})" for k in unique_ids_k])
        plt.savefig(os.path.join(output_dir, 'global_kmeans_clusters.png'), dpi=300, bbox_inches='tight')
        plt.close()
        print("Saved global_kmeans_clusters.png")
        
    # HDBSCAN
    print("Processing HDBSCAN visualization...")
    X_hdbscan_10d = getattr(umap_hdbscan, 'embedding_', None)
    labels_hdbscan = hdbscan.labels_
    
    unique_h, counts_h = np.unique(labels_hdbscan, return_counts=True)
    count_dict_h = dict(zip(unique_h, counts_h))
    
    if X_hdbscan_10d is not None:
        if X_hdbscan_10d.shape[0] > 10000:
            print("Subsampling HDBSCAN data to 10,000 points for faster visualization...")
            np.random.seed(42)
            idx = np.random.choice(X_hdbscan_10d.shape[0], 10000, replace=False)
            X_hdbscan_10d = X_hdbscan_10d[idx]
            labels_hdbscan = labels_hdbscan[idx]
            
        print(f"Projecting HDBSCAN 10D to 2D (size: {X_hdbscan_10d.shape})...")
        reducer_2d = umap.UMAP(n_components=2, n_neighbors=50, min_dist=0.0, n_jobs=-1, verbose=True)
        X_hdbscan_2d = reducer_2d.fit_transform(X_hdbscan_10d)
        
        # In HDBSCAN, -1 is noise
        core_mask = labels_hdbscan != -1
        noise_mask = labels_hdbscan == -1
        
        plt.figure(figsize=(12, 10))
        # Plot noise first as light grey
        plt.scatter(X_hdbscan_2d[noise_mask, 0], X_hdbscan_2d[noise_mask, 1], c='lightgrey', s=1, alpha=0.3, label='Noise')
        # Plot clusters
        scatter = plt.scatter(X_hdbscan_2d[core_mask, 0], X_hdbscan_2d[core_mask, 1], c=labels_hdbscan[core_mask], cmap='tab20', s=2, alpha=0.6)
        if np.sum(core_mask) > 1 and len(np.unique(labels_hdbscan[core_mask])) > 1:
            score = silhouette_score(X_hdbscan_10d[core_mask], labels_hdbscan[core_mask], random_state=42)
        else:
            score = 0
        plt.title(f'Global HDBSCAN Clusters (41 Benchmarks)\nUMAP(n_neighbors={umap_hdbscan.n_neighbors}, min_dist={umap_hdbscan.min_dist}) | HDBSCAN(min_cluster_size={hdbscan.min_cluster_size}) | Silhouette (Core): {score:.4f}')
        cbar = plt.colorbar(scatter, label='Cluster ID (Point Count)')
        unique_ids_h = sorted([k for k in count_dict_h.keys() if k != -1])
        cbar.set_ticks(unique_ids_h)
        cbar.ax.tick_params(labelsize=8)
        cbar.set_ticklabels([f"{k} ({count_dict_h[k]})" for k in unique_ids_h])
        
        # Also print noise count on plot
        noise_count = count_dict_h.get(-1, 0)
        plt.text(0.01, 0.01, f'Noise Points: {noise_count}', transform=plt.gca().transAxes, fontsize=10, bbox=dict(facecolor='white', alpha=0.8))
        plt.savefig(os.path.join(output_dir, 'global_hdbscan_clusters.png'), dpi=300, bbox_inches='tight')
        plt.close()
        print("Saved global_hdbscan_clusters.png")

if __name__ == "__main__":
    main()
