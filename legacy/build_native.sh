#!/usr/bin/env bash

echo "Building i2c_intercept shared library 🔨"

# Ensure the script is run from the correct directory
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$script_dir"

OPTIMIZATION_LEVEL="-O2"
# Always include _GNU_SOURCE to ensure RTLD_NEXT is available
BASE_FLAGS="-D_GNU_SOURCE"

# Assume we're compiling on an x86 runner.
# Native Linux build
echo "Building natively for Linux"
CC="gcc"
EXTRA_FLAGS=""

echo "Using compiler: $CC with optimization level: $OPTIMIZATION_LEVEL"

# The actual build command
$CC -shared -fPIC $OPTIMIZATION_LEVEL $BASE_FLAGS $EXTRA_FLAGS -o i2c_intercept.so i2c_intercept.c util.c -ldl

if [ $? -ne 0 ]; then
    echo "Error: Failed to build i2c_intercept shared library ❌"
    exit 1
fi

file i2c_intercept.so

echo "i2c_intercept shared library built successfully 📚"