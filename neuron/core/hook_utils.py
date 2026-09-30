import torch

class ActivationExtractor:
    def __init__(self, model, layer_idx):
        """
        layer_idx: int, e.g., 10 for layer index 10
        """
        self.model = model
        self.layer_idx = layer_idx
        self.activations = {}
        self.hooks = []
        
        if model.config.model_type == 'modernbert':
            self.down_projection = model.layers[layer_idx].mlp.Wo
            self.key = f'layers.{layer_idx}.mlp.Wo.input'
            self.hooks.append(self.down_projection.register_forward_pre_hook(self.capture_input))
        else:
            self.down_projection = model.encoder.layer[layer_idx].output.dense
            self.key = f'encoder.layer.{layer_idx}.intermediate'
            self.hooks.append(model.encoder.layer[layer_idx].intermediate.register_forward_hook(
                self.get_hook(self.key)))

    def capture_input(self, module, inputs):
        # GEGLU activation: GELU(Wi_first h) * (Wi_second h), after eval dropout.
        activation = inputs[0]
        if activation.ndim != 3:
            raise ValueError('Expected padded [batch, tokens, neurons]; use SDPA and disable compile')
        self.activations[self.key] = activation.detach().float().cpu()

    @property
    def activation(self):
        return self.activations[self.key]

    def get_hook(self, name):
        def hook(module, input, output):
            # output of intermediate is tensor of shape (batch, seq_len, intermediate_size)
            activation = output[0] if isinstance(output, tuple) else output
            self.activations[name] = activation.detach().cpu()
        return hook

    def get_down_projection_weights(self):
        """
        Returns the weights of the down-projection layer (ModernBERT mlp.Wo).
        Shape: (out_features, in_features) -> (hidden_size, intermediate_size)
        We transpose it to (intermediate_size, hidden_size) so that the i-th row corresponds to the i-th neuron r_i.
        """
        # weight shape is (hidden_size, intermediate_size) in PyTorch Linear
        weight = self.down_projection.weight.detach().float().cpu()
        return weight.T # shape: (intermediate_size, hidden_size)

    def clear(self):
        self.activations = {}

    def remove_hooks(self):
        for hook in self.hooks:
            hook.remove()
