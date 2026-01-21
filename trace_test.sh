#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./run_trace_and_diff.sh <input_dir> <verified_dir> [actual_out_dir]

TRACE_BIN="${TRACE_BIN:-./trace}"
DIFF_CMD="${DIFF_CMD:-diff -u}"

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <input_dir> <verified_dir> [actual_out_dir]" >&2
  exit 2
fi

INPUT_DIR="$(cd "$1" && pwd)"
VERIFIED_DIR="$(cd "$2" && pwd)"
ACTUAL_DIR="${3:-./trace_actual}"

if [[ ! -x "$TRACE_BIN" ]]; then
  echo "Error: TRACE_BIN '$TRACE_BIN' not found or not executable." >&2
  exit 2
fi
if [[ ! -d "$INPUT_DIR" ]]; then
  echo "Error: input_dir '$INPUT_DIR' is not a directory." >&2
  exit 2
fi
if [[ ! -d "$VERIFIED_DIR" ]]; then
  echo "Error: verified_dir '$VERIFIED_DIR' is not a directory." >&2
  exit 2
fi

mkdir -p "$ACTUAL_DIR"
ACTUAL_DIR="$(cd "$ACTUAL_DIR" && pwd)"

total=0
ran=0
missing_expected=0
mismatched=0
trace_failed=0

# Only find *.pcap files
while IFS= read -r -d '' in_file; do
  ((total++))

  rel="${in_file#$INPUT_DIR/}"

  # Strip .pcap and replace with .out
  base="${rel%.pcap}"
  expected="$VERIFIED_DIR/$base.out"
  actual="$ACTUAL_DIR/$base.out"

  mkdir -p "$(dirname "$actual")"

  if [[ ! -f "$expected" ]]; then
    echo "[MISSING EXPECTED] $base.out"
    ((missing_expected++))
    continue
  fi

  if ! "$TRACE_BIN" "$in_file" >"$actual"; then
    echo "[TRACE FAILED] $rel"
    ((trace_failed++))
    continue
  fi
  ((ran++))

  if ! $DIFF_CMD "$expected" "$actual" >/dev/null; then
    echo "[DIFF MISMATCH] $base.out"
    $DIFF_CMD "$expected" "$actual" || true
    ((mismatched++))
  else
    echo "[OK] $base.out"
  fi
done < <(find "$INPUT_DIR" -type f -name '*.pcap' -print0 | sort -z)

echo
echo "===== Summary ====="
echo "Total .pcap files:      $total"
echo "Ran trace:              $ran"
echo "Missing expected:       $missing_expected"
echo "Trace failures:         $trace_failed"
echo "Diff mismatches:        $mismatched"
echo "Actual outputs in:      $ACTUAL_DIR"
echo "====================="

if (( missing_expected > 0 || trace_failed > 0 || mismatched > 0 )); then
  exit 1
fi

