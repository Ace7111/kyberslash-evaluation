#!/usr/bin/env bash
# Captures host/toolchain state into results/logs/system_manifest_<timestamp>.txt
# Run before every principal build so hardware/toolchain drift is recorded per experiment.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/results/logs"
mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_DIR/system_manifest_${STAMP}.txt"

{
  echo "# System manifest captured ${STAMP}"
  echo
  echo "## uname"
  # Hostname is redacted: it identifies the machine's owner and contributes nothing
  # to reproducibility, whereas kernel, version and architecture do.
  uname -a | sed "s/$(hostname -s)[^ ]*/[redacted-hostname]/g"

  echo
  echo "## OS release"
  if [ -f /etc/os-release ]; then
    cat /etc/os-release
  elif command -v sw_vers >/dev/null 2>&1; then
    sw_vers
  fi

  echo
  echo "## CPU"
  if command -v lscpu >/dev/null 2>&1; then
    lscpu
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n machdep.cpu.brand_string 2>/dev/null || true
    sysctl hw.ncpu hw.physicalcpu hw.logicalcpu hw.memsize hw.cachelinesize hw.l1dcachesize hw.l2cachesize 2>/dev/null || true
  fi

  echo
  echo "## Scaling governor (Linux only, best effort)"
  cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "not available on this platform"

  echo
  echo "## Toolchain: git"
  git --version

  echo
  echo "## Toolchain: system clang"
  clang --version 2>&1 || echo "not found"

  echo
  echo "## Toolchain: Homebrew gcc-16 (or nearest available gcc-*)"
  gcc_bin="$(command -v gcc-16 || ls /opt/homebrew/bin/gcc-* 2>/dev/null | head -1 || true)"
  if [ -n "${gcc_bin:-}" ]; then
    "$gcc_bin" -v
  else
    echo "not found"
  fi

  echo
  echo "## Toolchain: cmake"
  cmake --version 2>&1 || echo "not found"

  echo
  echo "## Toolchain: ninja"
  ninja --version 2>&1 || echo "not found"

  echo
  echo "## Toolchain: make"
  make --version 2>&1 | head -3 || echo "not found"

  echo
  echo "## Toolchain: python3"
  python3 --version

  echo
  echo "## Toolchain: objdump"
  objdump --version 2>&1 | head -3 || echo "not found"

  echo
  echo "## ld"
  ld -v 2>&1 | head -3 || true

} > "$OUT" 2>&1

echo "Wrote $OUT"
