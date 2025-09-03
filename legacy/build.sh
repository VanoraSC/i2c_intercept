#!/usr/bin/env bash

echo "Building i2c_intercept shared library 🔨"

# Ensure the script is run from the correct directory
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$script_dir"

TARGET="aarch64-unknown-linux-gnu"
OPTIMIZATION_LEVEL="-O2"
# Always include _GNU_SOURCE to ensure RTLD_NEXT is available
BASE_FLAGS="-D_GNU_SOURCE"

# Determine if we're cross-compiling
if [[ "$(uname -m)" == "aarch64" && "$(uname -s)" == "Linux" ]]; then
    # Native ARM Linux build
    echo "Building natively for ARM Linux"
    CC="gcc"
    EXTRA_FLAGS=""
else
    # Cross-compilation setup
    echo "Cross-compiling for ARM Linux ($TARGET)"
    
    # Check for cross-compiler based on platform
    if [[ "$(uname -s)" == "Darwin" ]]; then
        # macOS - check for installed cross compiler via Homebrew
        if command -v aarch64-linux-gnu-gcc &> /dev/null; then
            CC="aarch64-linux-gnu-gcc"
        else
            echo "Error: Cross compiler not found."
            exit 1
        fi
        # No need for extra flags since we already have BASE_FLAGS
        EXTRA_FLAGS=""
    elif [[ "$(uname -s)" == "Linux" ]]; then
        # Linux (non-ARM) - use standard cross compiler packages
        if command -v aarch64-linux-gnu-gcc &> /dev/null; then
            CC="aarch64-linux-gnu-gcc"
        else
            echo "Error: Cross compiler not found."
            exit 1
        fi
        EXTRA_FLAGS=""
    elif [[ "$(uname -s)" =~ MINGW|MSYS|CYGWIN ]]; then
        # Windows 🤢
        if command -v aarch64-linux-gnu-gcc &> /dev/null; then
            CC="aarch64-linux-gnu-gcc"
        else
            echo "Error: Cross compiler not found."
            exit 1
        fi
        EXTRA_FLAGS=""
    else
        echo "Error: Unsupported build platform. Please install an appropriate cross-compiler for $TARGET"
        exit 1
    fi
fi

echo "Using compiler: $CC with optimization level: $OPTIMIZATION_LEVEL"

# The actual build command
$CC -shared -fPIC $OPTIMIZATION_LEVEL $BASE_FLAGS $EXTRA_FLAGS -o i2c_intercept.so i2c_intercept.c util.c -ldl

if [ $? -ne 0 ]; then
    echo "Error: Failed to build i2c_intercept shared library ❌"
    exit 1
fi

file i2c_intercept.so

echo "i2c_intercept shared library built successfully 📚"