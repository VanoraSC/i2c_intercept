#!/usr/bin/env bash
# Configure environment variables so the I²C redirect library forwards traffic
# through a serial TTY tap server without touching real I²C hardware.
#
# This script should be sourced to modify the current shell environment.  It
# sets:
#   I2C_SOCAT_TTY      - Serial device to bridge (default: /dev/ttyS22)
#   I2C_SOCAT_SOCKET   - Unix socket used by the socat helper
#   I2C_PROXY_SOCK     - Socket the preload library connects to
#   LD_PRELOAD         - Path to the preload library
# It also unsets I2C_PROXY_PASSTHROUGH to prevent access to actual I²C buses.

# Serial device used for tapping; override by pre-setting I2C_SOCAT_TTY.
export I2C_SOCAT_TTY="${I2C_SOCAT_TTY:-/dev/ttyS22}"
# Socket path for the socat bridge; default derives from device name.
export I2C_SOCAT_SOCKET="${I2C_SOCAT_SOCKET:-/tmp/ttyS22.tap.sock}"
# The preload library connects to the same socket exposed by socat.
export I2C_PROXY_SOCK="$I2C_SOCAT_SOCKET"
# Disable passthrough so intercepted calls never reach real I²C hardware.
unset I2C_PROXY_PASSTHROUGH
# Point LD_PRELOAD at the interception library located in the current
# working directory.  Users may override LD_PRELOAD to supply a different
# path but by default a relative path is used so this script functions in any
# directory containing libi2c_redirect.so.
export LD_PRELOAD="${LD_PRELOAD:-./libi2c_redirect.so}"

# Provide a summary for the user.
echo "TTY tap environment configured:"
echo "  I2C_SOCAT_TTY=$I2C_SOCAT_TTY"
echo "  I2C_SOCAT_SOCKET=$I2C_SOCAT_SOCKET"
echo "  I2C_PROXY_SOCK=$I2C_PROXY_SOCK"
echo "  I2C_PROXY_PASSTHROUGH is unset"
echo "  LD_PRELOAD=$LD_PRELOAD"

