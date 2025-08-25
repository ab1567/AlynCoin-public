#!/bin/bash
set -e
g++ -std=c++17 -Isrc tests/formatting_test.cpp src/utils/format.cpp -o tests/formatting_test
./tests/formatting_test
