#!/bin/bash

# Variables
SRV_BIN="./bin/ot_srv"
BLD_SH="./build.sh"
LOG_FILE="test_run.log"
TEST_FILES=("./bin/test_pkt" "./bin/test_srv" "./bin/test_srv_runtime")

# Clear out any old log file from previous runs
> "$LOG_FILE"

# 1. Build the project
if [ -f "$BLD_SH" ]; then
  echo "Building project..."
  $BLD_SH
  
  if [ $? -ne 0 ]; then
    echo "Build failed. Exiting..."
    exit 1
  fi
fi

# 2. Start the server
if [ -f "$SRV_BIN" ]; then
  echo "Starting server..."
  $SRV_BIN &
  PID_SRV_BIN=$!
  sleep 1 
else 
  echo "$SRV_BIN does not exist. Exiting..."
  exit 1
fi

# 3. Run the tests
for test_file in "${TEST_FILES[@]}"; do
    if [ -x "$test_file" ]; then
        echo "-----------------------------------"
        echo "Running: $test_file"
        
        # Run the test, combine errors with standard output (2>&1), 
        # and use 'tee' to print to the screen AND append to the log file.
        "$test_file" 2>&1 | tee -a "$LOG_FILE"
        
        # Note: Because we used a pipe (|), $? would give us the exit code of 'tee'.
        # To get the exit code of our test program, we use PIPESTATUS[0].
        if [ ${PIPESTATUS[0]} -ne 0 ]; then 
            echo "$test_file returned an error code!"
            # We don't exit here anymore. We let the loop finish to gather all failures.
        fi
    else
        echo "Skipping: $test_file (not executable)"
    fi
done

# 4. Clean up
echo "-----------------------------------"
echo "Shutting down server..."
kill $PID_SRV_BIN

# 5. Print the Final Summary
echo -e "\n=== TEST SUMMARY ==="

# Search the log file for the exact string "[FAILED]"
FAILED_LINES=$(grep "\[FAILED\]" "$LOG_FILE")

# If FAILED_LINES is not empty (-n), print the lines and exit with an error
if [ -n "$FAILED_LINES" ]; then
    echo "$FAILED_LINES"
    exit 1
else
    # If it is empty, everything passed
    echo "ALL TESTS PASSED"
    exit 0
fi
