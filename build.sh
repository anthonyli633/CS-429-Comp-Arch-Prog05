#!/bin/bash
set -e

rm -f hw5-asm hw5-sim

gcc -std=c11 -Wall -Wextra -O2 hw3.c -o hw5-asm
gcc -std=c11 -Wall -Wextra -O2 hw4.c -o hw5-sim
