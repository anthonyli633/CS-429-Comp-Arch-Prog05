#!/bin/bash
set -e

rm -f hw5-asm hw5-sim

gcc -std=c11 -Wall -Wextra -O2 hw5-asm.o -o hw5-asm
gcc -std=c11 -Wall -Wextra -O2 hw5-sim.o -o hw5-sim
