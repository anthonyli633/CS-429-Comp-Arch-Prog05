#!/usr/bin/env bash
set -euo pipefail

ASM="${ASM:-./hw5-asm}"
SIM="${SIM:-./hw5-sim}"
FIB_TK="${FIB_TK:-fibonacci.tk}"
BS_TK="${BS_TK:-binary_search.tk}"
MM_TK="${MM_TK:-matrix_multiplication.tk}"

TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

need python3
[[ -x "$ASM" ]] || fail "assembler not found/executable: $ASM"
[[ -x "$SIM" ]] || fail "simulator not found/executable: $SIM"
[[ -f "$FIB_TK" ]] || fail "missing $FIB_TK"
[[ -f "$BS_TK"  ]] || fail "missing $BS_TK"
[[ -f "$MM_TK"  ]] || fail "missing $MM_TK"

assemble() {
  local in_tk="$1"
  local out_tko="$2"
  "$ASM" "$in_tk" "$out_tko"
}

runprog() {
  local prog="$1"
  local input="$2"
  "$SIM" "$prog" < "$input"
}

# Helper: IEEE-754 double -> uint64 (prints as decimal)
dbl_u64() {
  python3 - <<'PY'
import struct, sys
x=float(sys.argv[1])
u=struct.unpack("<Q", struct.pack("<d", x))[0]
print(u)
PY
}

# Convenience: create a file with whitespace-separated ints
mk_input() {
  local path="$1"; shift
  : > "$path"
  for x in "$@"; do
    printf "%s\n" "$x" >> "$path"
  done
}

# Fibonacci Tests
echo "== Assembling Fibonacci =="
FIB_TKO="$TMP_DIR/fib.tko"
assemble "$FIB_TK" "$FIB_TKO"

echo "== Running Fibonacci =="
FIB_IN="$TMP_DIR/fib.in"
mk_input "$FIB_IN" 1

FIB_OUT="$TMP_DIR/fib.out"
runprog "$FIB_TKO" "$FIB_IN" > "$FIB_OUT"

FIB_EXPECT="$TMP_DIR/fib.expected"
printf "0\n" > "$FIB_EXPECT"

if diff -u "$FIB_EXPECT" "$FIB_OUT" >/dev/null; then
  echo "PASS: Fibonacci"
else
  echo "---- Fibonacci expected ----"; cat "$FIB_EXPECT"
  echo "---- Fibonacci got ----"; cat "$FIB_OUT"
  fail "Fibonacci output mismatch (adjust expectation in tests.sh if your spec differs)"
fi

echo "== Running Fibonacci =="
FIB_IN="$TMP_DIR/fib.in"
mk_input "$FIB_IN" 2

FIB_OUT="$TMP_DIR/fib.out"
runprog "$FIB_TKO" "$FIB_IN" > "$FIB_OUT"

FIB_EXPECT="$TMP_DIR/fib.expected"
printf "1\n" > "$FIB_EXPECT"

if diff -u "$FIB_EXPECT" "$FIB_OUT" >/dev/null; then
  echo "PASS: Fibonacci"
else
  echo "---- Fibonacci expected ----"; cat "$FIB_EXPECT"
  echo "---- Fibonacci got ----"; cat "$FIB_OUT"
  fail "Fibonacci output mismatch (adjust expectation in tests.sh if your spec differs)"
fi

echo "== Running Fibonacci =="
FIB_IN="$TMP_DIR/fib.in"
mk_input "$FIB_IN" 11

FIB_OUT="$TMP_DIR/fib.out"
runprog "$FIB_TKO" "$FIB_IN" > "$FIB_OUT"

# fib(11) = 55 (with fib(1)=0, fib(1)=1)
FIB_EXPECT="$TMP_DIR/fib.expected"
printf "55\n" > "$FIB_EXPECT"

if diff -u "$FIB_EXPECT" "$FIB_OUT" >/dev/null; then
  echo "PASS: Fibonacci"
else
  echo "---- Fibonacci expected ----"; cat "$FIB_EXPECT"
  echo "---- Fibonacci got ----"; cat "$FIB_OUT"
  fail "Fibonacci output mismatch (adjust expectation in tests.sh if your spec differs)"
fi

# Binary Search Tests
echo "== Assembling Binary Search =="
BS_TKO="$TMP_DIR/bs.tko"
assemble "$BS_TK" "$BS_TKO"

echo "== Running Binary Search (found case) =="
BS_FOUND_IN="$TMP_DIR/bs_found.in"
# n=5, list: 1 3 5 7 9, query=7
mk_input "$BS_FOUND_IN" 5 1 3 5 7 9 7

BS_FOUND_OUT="$TMP_DIR/bs_found.out"
runprog "$BS_TKO" "$BS_FOUND_IN" > "$BS_FOUND_OUT"

BS_FOUND_EXPECT="$TMP_DIR/bs_found.expected"
printf "found\n" > "$BS_FOUND_EXPECT"

if diff -u "$BS_FOUND_EXPECT" "$BS_FOUND_OUT" >/dev/null; then
  echo "PASS: Binary Search (found)"
else
  echo "---- BS(found) expected ----"; cat "$BS_FOUND_EXPECT"
  echo "---- BS(found) got ----"; cat "$BS_FOUND_OUT"
  fail "Binary Search found-case mismatch"
fi

echo "== Running Binary Search (not found case) =="
BS_NF_IN="$TMP_DIR/bs_nf.in"
# n=5, list: 1 3 5 7 9, query=8
mk_input "$BS_NF_IN" 5 1 3 5 7 9 8

BS_NF_OUT="$TMP_DIR/bs_nf.out"
runprog "$BS_TKO" "$BS_NF_IN" > "$BS_NF_OUT"

BS_NF_EXPECT="$TMP_DIR/bs_nf.expected"
printf "not found\n" > "$BS_NF_EXPECT"

if diff -u "$BS_NF_EXPECT" "$BS_NF_OUT" >/dev/null; then
  echo "PASS: Binary Search (not found)"
else
  echo "---- BS(notfound) expected ----"; cat "$BS_NF_EXPECT"
  echo "---- BS(notfound) got ----"; cat "$BS_NF_OUT"
  fail "Binary Search notfound-case mismatch"
fi

# =========================
# Test 3: Matrix Multiplication (double bits in/out as uint64)
# Input: dim n, then A row-major (n*n doubles), then B row-major (n*n doubles)
# Output: C row-major (n*n doubles) printed as uint64 on port 1
# We'll test n=2 with:
# A = [[1,2],[3,4]], B = [[5,6],[7,8]]
# C = [[19,22],[43,50]]
# =========================
echo "== Assembling Matrix Multiplication =="
MM_TKO="$TMP_DIR/mm.tko"
assemble "$MM_TK" "$MM_TKO"

echo "== Running Matrix Multiplication =="
MM_IN="$TMP_DIR/mm.in"

python3 - <<'PY' > "$MM_IN"
import struct
def u64(d):
    return struct.unpack("<Q", struct.pack("<d", float(d)))[0]

n = 2
A = [1.0, 2.0, 3.0, 4.0]
B = [5.0, 6.0, 7.0, 8.0]

print(n)
for x in A: print(u64(x))
for x in B: print(u64(x))
PY

MM_OUT="$TMP_DIR/mm.out"
runprog "$MM_TKO" "$MM_IN" > "$MM_OUT"

MM_EXPECT="$TMP_DIR/mm.expected"
python3 - <<'PY' > "$MM_EXPECT"
import struct
def u64(d):
    return struct.unpack("<Q", struct.pack("<d", float(d)))[0]
C = [19.0, 22.0, 43.0, 50.0]
for x in C: print(u64(x))
PY

if diff -u "$MM_EXPECT" "$MM_OUT" >/dev/null; then
  echo "PASS: Matrix Multiplication"
else
  echo "---- MatMul expected ----"; cat "$MM_EXPECT"
  echo "---- MatMul got ----"; cat "$MM_OUT"
  fail "Matrix multiplication output mismatch"
fi

echo "========================="
echo "ALL TESTS PASSED"
echo "========================="