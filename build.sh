#!/bin/bash

# Navigate to your test directory if necessary
cmake -S . -B build && cd build && make clean && make

