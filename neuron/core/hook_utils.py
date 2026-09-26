import torch

class ActivationExtractor:
    def __init__(self, model, layer_idx):
        """
        layer_idx: int, e.g., 10 for the 10th layer of CodeBERT
        """
        self.model = model
        self.layer_idx = layer_idx
        self.activations = {}
        self.hooks = []
        
        # In CodeBERT, the MLP consists of intermediate.dense (in=768, out=3072)
        # followed by intermediate_act_fn (GELU), and then output.dense (in=3072, out=768)
        # We want the activation after GELU, which is the output of 'intermediate'.
        # However, to be safe and avoid activation function complications if any, 
        # we can hook into intermediate's forward, or just hook 'intermediate'.
        
        target_module_name = f"encoder.layer.{layer_idx}.intermediate"
        
        for name, module in self.model.named_modules():
            if name == target_module_name:
                self.hooks.append(module.register_forward_hook(self.get_hook(name)))
                
    def get_hook(self, name):
        def hook(module, input, output):
            # output of intermediate is tensor of shape (batch, seq_len, 3072)
            activation = output[0] if isinstance(output, tuple) else output
            self.activations[name] = activation.detach().cpu()
        return hook

    def get_down_projection_weights(self):
        """
        Returns the weights of the down-projection layer (output.dense).
        Shape: (out_features, in_features) -> (768, 3072)
        We transpose it to (3072, 768) so that the i-th row corresponds to the i-th neuron r_i.
        """
        # weight shape is (768, 3072) in PyTorch Linear
        weight = self.model.encoder.layer[self.layer_idx].output.dense.weight.detach().cpu()
        return weight.T # shape: (3072, 768)

    def clear(self):
        self.activations = {}

    def remove_hooks(self):
        for hook in self.hooks:
            hook.remove()
