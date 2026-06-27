# Guided Fuzzing Framework

## pre settings

```bash
# kernel core file setting
echo "kernel.core_pattern = core" | sudo tee /etc/sysctl.d/99-core-pattern.conf
sudo sysctl --system
sysctl kernel.core_pattern

# disable apport
sudo systemctl stop apport
sudo systemctl disable apport

# disable core dump file size
ulimit -c 0

# CPU performance mode
sudo cpupower frequency-set -g performance
```

## Future Optimization Directions for CAFL (ARM & Scheduling)

### 1. Cull Queue & Favored Seed Selection
- **Issue with Fixed Threshold**: Marking seeds with `arm_depth >= 2` as `favored` causes priority inflation, making too many seeds favored and diluting the culling mechanism.
- **Proposed Optimization A (Peak Frontier Promotion)**: Dynamically track `max_arm_depth_in_queue` during culling. Only promote seeds that reach the current peak sequence depth (`arm_depth == max_arm_depth_in_queue`) to `favored`.
- **Proposed Optimization B (Pure Energy Allocation)**: Keep `cull_queue` 100% untouched to preserve traditional coverage-based mini-set culling, and rely exclusively on `calculate_score` for ARM sequence energy scaling.

### 2. Energy Scheduling in `calculate_score`
- **Noise Reduction**: Remove legacy coarse binary flags (`dgf_has_control`, `dgf_has_caller`) from the `if-else` chain.
- **Unified Sequence Scheduling**: Streamline `calculate_score` to prioritize the final CVE target (`dgf_has_target`), while all intermediate control-flow progress is guided continuously by ARM sequence depth (`arm_depth`).