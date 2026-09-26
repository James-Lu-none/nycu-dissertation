import torch

def calculate_neuron_contributions(line_activations, down_proj_weights):
    """
    Calculate the contribution of each neuron based on line-level activations.
    line_activations: Tensor of shape (num_samples, hidden_size) 
                      (already aggregated across relevant lines for each sample)
    down_proj_weights: Tensor of shape (hidden_size, embedding_size) -> (3072, 768)
                       where i-th row is r_i
    
    Returns: Tensor of shape (hidden_size,) containing contribution scores.
    """
    # Mean activation across all samples: shape (hidden_size,)
    mean_activations = line_activations.mean(dim=0)
    
    # Calculate L2 norm of down-projection weights for each neuron
    # norm(r_i) for all i: shape (hidden_size,)
    r_norms = torch.norm(down_proj_weights, p=2, dim=1)
    
    # Contribution c_i = a_i * ||r_i||
    contributions = mean_activations * r_norms
    
    return contributions

def get_top_k_neurons(contributions, k_ratio=0.03):
    """
    Get indices of the top-K neurons based on contribution score.
    k_ratio: float, ratio of total neurons to select (e.g., 0.03 for 3%)
    """
    num_neurons = contributions.shape[0]
    k = max(1, int(num_neurons * k_ratio))
    
    # Get top K indices
    top_k_vals, top_k_indices = torch.topk(contributions, k)
    
    # Return as a set for easy subtraction later
    return set(top_k_indices.tolist())

def get_vulnerability_specific_neurons(vul_contributions, ben_contributions, k_ratio=0.03):
    """
    N_r,l = N_v,l - N_p,l
    """
    N_v = get_top_k_neurons(vul_contributions, k_ratio)
    N_p = get_top_k_neurons(ben_contributions, k_ratio)
    
    N_r = N_v - N_p
    return list(N_r)
