#!/usr/bin/env bash
# Configure environment variables to route I²C traffic through the i2c tap
# server without accessing any real hardware.
#
# The script should be sourced so that the exports affect the current shell.
# It defines the following variables:
#   I2C_PROXY_SOCK     - Unix socket used by the tap server (default: /tmp/i2c.tap.sock)
#   LD_PRELOAD         - Path to the preload library that intercepts I²C calls
# The variable I2C_PROXY_PASSTHROUGH is explicitly unset to prevent real bus
# accesses.  After sourcing this file run the desired I²C program normally and
# all calls will be forwarded to the tap server.

# Use caller supplied socket path or fall back to the default.
export I2C_PROXY_SOCK="${I2C_PROXY_SOCK:-/tmp/i2c.tap.sock}"
# Ensure passthrough is disabled so no real I²C hardware is accessed.
unset I2C_PROXY_PASSTHROUGH
# Point LD_PRELOAD at the interception library located in the current
# working directory.  If LD_PRELOAD is already set the existing value is
# preserved; otherwise a relative path is used so the caller can position
# the library as needed.
export LD_PRELOAD="${LD_PRELOAD:-./libi2c_redirect.so}"

# Provide a brief summary so users know the configuration in effect.
echo "I2C tap environment configured:"
echo "  I2C_PROXY_SOCK=$I2C_PROXY_SOCK"
echo "  I2C_PROXY_PASSTHROUGH is unset"
echo "  LD_PRELOAD=$LD_PRELOAD"

