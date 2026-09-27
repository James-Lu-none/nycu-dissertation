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

# # Old Set Difference Logic
# def get_top_k_neurons(contributions, k_ratio=0.03):
#     num_neurons = contributions.shape[0]
#     k = max(1, int(num_neurons * k_ratio))
#     top_k_vals, top_k_indices = torch.topk(contributions, k)
#     return set(top_k_indices.tolist())
#
# def get_vulnerability_specific_neurons(vul_contributions, ben_contributions, k_ratio=0.03):
#     """
#     N_r,l = N_v,l - N_p,l
#     """
#     N_v = get_top_k_neurons(vul_contributions, k_ratio)
#     N_p = get_top_k_neurons(ben_contributions, k_ratio)
#     N_r = N_v - N_p
#     return list(N_r)

def get_vulnerability_specific_neurons(vul_activations, ben_activations, down_proj_weights, k_ratio=0.10):
    """
    New Logic: Paired Difference of Contribution
    vul_activations: Tensor of shape (num_samples, hidden_size)
    ben_activations: Tensor of shape (num_samples, hidden_size)
    down_proj_weights: Tensor of shape (hidden_size, embedding_size)
    """
    # 1. Calculate L2 norm of down-projection weights for each neuron
    # ||r_i||_2 for all i: shape (hidden_size,)
    r_norms = torch.norm(down_proj_weights, p=2, dim=1)
    
    # 2. For each pair j, calculate contribution difference: delta_c_j = c_V_j - c_P_j
    # Since c_V_j = a_V_j * ||r||, and c_P_j = a_P_j * ||r||
    # delta_c_j = (a_V_j - a_P_j) * ||r||
    delta_activations = vul_activations - ben_activations # (num_samples, hidden_size)
    delta_contributions = delta_activations * r_norms # (num_samples, hidden_size)
    
    # 3. Take mean value of contribution difference across all patch pairs
    mean_delta_c = delta_contributions.mean(dim=0) # (hidden_size,)
    
    # 4. Obtain the final top K vulnerability-specific neuron set directly
    num_neurons = mean_delta_c.shape[0]
    k = max(1, int(num_neurons * k_ratio))
    
    # top_k returns values and indices. We just need the indices.
    top_k_vals, top_k_indices = torch.topk(mean_delta_c, k)
    
    return top_k_indices.tolist()
