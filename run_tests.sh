#!/bin/bash

#Build project first
./build.sh
cd bin

for test_file in ./test_*; do
    if [ -x "$test_file" ]; then
        echo "Running: $test_file"
        "$test_file"
        if [ $? -eq 1 ]; then 
          echo "run_tests.sh: one or more tests have failed! Exiting..."
          exit 1
        fi
    else
        echo "Skipping: $test_file (not executable)"
    fi
done

exit 0
