import torch

def compute_line_representation(line_activation, target_neurons, down_proj_weights):
    """
    Compute the vulnerability-neuron representation p_l for a specific line.
    line_activation: Tensor of shape (hidden_size,) -> a_l^q
    target_neurons: list of int -> N_r,l
    down_proj_weights: Tensor of shape (hidden_size, embedding_size) -> (3072, 768)
    
    Returns: Tensor of shape (embedding_size,) -> (768,)
    """
    # Extract only the target neurons
    indices = torch.tensor(target_neurons, dtype=torch.long)
    
    a_subset = line_activation[indices] # shape: (len(target_neurons),)
    r_subset = down_proj_weights[indices] # shape: (len(target_neurons), embedding_size)
    
    # p_l = sum(a_i * r_i)
    # Using matrix multiplication: (1, N) @ (N, E) -> (1, E)
    p_l = torch.matmul(a_subset.unsqueeze(0), r_subset).squeeze(0)
    return p_l

def compute_vulnerability_direction(vul_reps, ben_reps):
    """
    Method A (Global Average):
    vul_reps: Tensor of shape (num_vul_samples, embedding_size)
    ben_reps: Tensor of shape (num_ben_samples, embedding_size)
    """
    P_v = vul_reps.mean(dim=0)
    P_p = ben_reps.mean(dim=0)
    
    d_v = P_v - P_p
    return d_v

def compute_pairwise_vulnerability_direction(vul_reps, ben_reps):
    """
    Method B (Pairwise Average):
    Requires vul_reps and ben_reps to be paired (same length).
    """
    assert vul_reps.shape == ben_reps.shape
    diffs = vul_reps - ben_reps
    d_v = diffs.mean(dim=0)
    return d_v

def score_target_line(target_line_rep, d_v):
    """
    Project the line representation onto the vulnerability direction.
    target_line_rep: Tensor of shape (..., embedding_size)
    d_v: Tensor of shape (embedding_size,)
    
    Returns: signed scalar projection per representation, with shape (...,).
    A zero direction returns zero scores.
    """
    d_v_norm = torch.norm(d_v)
    
    if d_v_norm == 0:
        return target_line_rep.new_zeros(target_line_rep.shape[:-1])
        
    return torch.matmul(target_line_rep, d_v / d_v_norm)
