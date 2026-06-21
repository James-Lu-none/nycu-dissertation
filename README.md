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