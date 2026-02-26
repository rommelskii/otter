# Otter

A TCP-based authentication server and protocol suite for authenticating user details

## Features

- **Tethering:** Client-server connection management via handshake transactions
- **Secure Authentication:** Implements credential hashing and salting
- **TCP Communication** Utilizes TCP sockets for communication between client and server

## Project Structure

- `include/`: Header files and public API definitions.
- `src/`: Core implementation of the Otter protocol and API.
- `examples/`: Sample programs demonstrating client and server implementation.
- `tests/`: Unit tests and protocol validation suites.

## Getting Started

### Prerequisites

- C compiler (GCC/Clang)
- CMake (version 3.10 or higher)

### Build Instructions

You can use the provided build script or run CMake manually:

```bash
# Using the build script
chmod +x build.sh
./build.sh

# Manual build
mkdir build && cd build
cmake ..
make
```

### Testing Instructions

To perform tests, you must perform:

```
chmod +x run_tests.sh
./run_tests.sh
```

