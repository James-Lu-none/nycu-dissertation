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

```bash
# settings for slurm
# disable /dev/shm auto clean with RemoveIPC
vim /etc/systemd/logind.conf
RemoveIPC=no
sudo systemctl restart systemd-logind
```

## build images

```bash
./manage.sh build dafl --tags v1
./manage.sh build cafl --tags v1

./manage.sh build muoafl --tags v1
./manage.sh build muoafl --tags v2
./manage.sh build muoafl --tags v3

./manage.sh build

# to docker registry
./manage.sh build dafl --tags v1 --registry docker.io/location0717
./manage.sh build cafl --tags v1 --registry docker.io/location0717

./manage.sh build muoafl --tags v1 --registry docker.io/location0717
./manage.sh build muoafl --tags v2 --registry docker.io/location0717
./manage.sh build muoafl --tags v3 --registry docker.io/location0717
./manage.sh build muoafl --tags v4 --registry docker.io/location0717

./manage.sh build --registry docker.io/location0717
```

## run benchmarks

### normal server (docker)

```bash
# v1: dafl + muofuzz (no interaction)
./loop.sh --tags v1 --trials 30
# v2: dafl + muofuzz (use dafl distance score as additional feedback)
./loop.sh --tags v2 --trials 30
# v3: dafl + muofuzz (use dafl distance score as additional feedback and add sematic)
./loop.sh --tags v3 --trials 30

./loop_all.sh --tags="v1,v2,v3" --trials 30

# from docker registry
./loop_all.sh --tags="v1,v2,v3" --trials 30 --registry docker.io/location0717
```

### slurm cluster (apptainer)

```bash
# v1: dafl + muofuzz (no interaction)
./loop_all.sh --tag v1 --slurm --trials 30
# v2: dafl + muofuzz (use dafl distance score as additional feedback)
./loop_all.sh --tag v2 --slurm --trials 30
# v3: dafl + muofuzz (use dafl distance score as additional feedback and add sematic)
./loop_all.sh --tag v3 --slurm --trials 30

./loop_all.sh --tags="v1,v2,v3" --trials 30 --slurm

# from docker registry
./loop_all.sh --tags="v1,v2,v3" --trials 30 --slurm --registry docker.io/location0717
```

## AFL++ Semantic Mutator Markov Chain Architecture

To effectively leverage semantic clusters during the havoc mutation phase, the architecture implements a Markov Chain model. This separates the selection of the initial mutator from the sequence of subsequent mutators.

in `struct queue_entry`, a variable `semantic_type` is added to store the dominant semantic cluster ID of the input. and used in `afl-fuzz-one.c` when obtaining sematic type of current seed queue with `afl->queue_cur->semantic_type` to update finds_per_semantic_mut

### 1. Initial State (First Mutator Selection)
When a mutation stack begins, there is no previous mutator (`prev_mutator == -1`). 
- **Selection**: To ensure a fair ablation study and direct comparison with `muoafl-v1`, the first mutator is selected purely randomly from the default mutation array (`mutation_array[rand_below(afl, rand_max)]`).
- **Reward**: Since the selection is purely random and unguided, we do not update any matrix for the first mutator. This strictly isolates our performance gains to the semantic transition matrix.

### 2. Transition State (Subsequent Mutators)
For the second mutator and onwards, the selection depends on the immediate predecessor, capturing mutator combinations (combos) specifically for the current cluster.
- **Probability Matrix**: Uses a 3D tensor (`Semantic * Prev_Mutator * Next_Mutator`), defined as `prob_table_semantic_mut`.
- **Logic**: Calls `sample_from_semantic_mut_distribution()` to select the next mutator based on both the semantic cluster and the `prev_mutator`.
- **Reward**: Rewards for subsequent mutators are applied to `finds_per_semantic_mut[sem_type][prev_mutator][current_mutator]`. This learns effective mutation sequences (e.g., splicing followed by bit-flipping) tailored to specific semantic clusters.

This design completely isolates the transition logic (Combos) from the initial selection, ensuring that any improvements observed in v3 over v1 are purely the result of the Semantic-Aware Transition Matrix.



## Future Optimization Directions for CAFL (ARM & Scheduling)

### 1. Cull Queue & Favored Seed Selection
- **Issue with Fixed Threshold**: Marking seeds with `arm_depth >= 2` as `favored` causes priority inflation, making too many seeds favored and diluting the culling mechanism.
- **Proposed Optimization A (Peak Frontier Promotion)**: Dynamically track `max_arm_depth_in_queue` during culling. Only promote seeds that reach the current peak sequence depth (`arm_depth == max_arm_depth_in_queue`) to `favored`.
- **Proposed Optimization B (Pure Energy Allocation)**: Keep `cull_queue` 100% untouched to preserve traditional coverage-based mini-set culling, and rely exclusively on `calculate_score` for ARM sequence energy scaling.

### 2. Energy Scheduling in `calculate_score`
- **Noise Reduction**: Remove legacy coarse binary flags (`dgf_has_control`, `dgf_has_caller`) from the `if-else` chain.
- **Unified Sequence Scheduling**: Streamline `calculate_score` to prioritize the final CVE target (`dgf_has_target`), while all intermediate control-flow progress is guided continuously by ARM sequence depth (`arm_depth`).