#!/usr/bin/env bash
# Configure environment variables to route I²C traffic through the i2c tap
# server without accessing any real hardware.  Passthrough support has been
# removed so intercepted commands are always proxied.
#
# The script should be sourced so that the exports affect the current shell.
# It defines the following variables:
#   I2C_PROXY_SOCK     - Unix socket used by the tap server (default: /tmp/i2c.tap.sock)
#   LD_PRELOAD         - Path to the preload library that intercepts I²C calls

# Use caller supplied socket path or fall back to the default.
export I2C_PROXY_SOCK="${I2C_PROXY_SOCK:-/tmp/i2c.tap.sock}"
# All traffic is automatically proxied; no passthrough variable is needed.
# Point LD_PRELOAD at the interception library located in the current
# working directory.  If LD_PRELOAD is already set the existing value is
# preserved; otherwise a relative path is used so the caller can position
# the library as needed.
export LD_PRELOAD="${LD_PRELOAD:-./libi2c_redirect.so}"

# Provide a brief summary so users know the configuration in effect.
echo "I2C tap environment configured:"
echo "  I2C_PROXY_SOCK=$I2C_PROXY_SOCK"
echo "  LD_PRELOAD=$LD_PRELOAD"

