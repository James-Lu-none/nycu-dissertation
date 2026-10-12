"""Patience tracks meaningful gains; checkpoint selection tracks every strict gain."""
import math


class EarlyStopping:
    def __init__(self, patience=5, min_delta=.001):
        if patience < 0 or not math.isfinite(min_delta) or min_delta < 0:
            raise ValueError('Invalid early-stopping configuration')
        self.patience = patience
        self.min_delta = min_delta
        self.reference = -math.inf
        self.stale = 0

    def update(self, value):
        if value is None or not math.isfinite(value):
            raise ValueError('Validation selection metric must be finite')
        if value > self.reference + self.min_delta:
            self.reference = value
            self.stale = 0
        else:
            self.stale += 1
        return self.patience > 0 and self.stale >= self.patience
