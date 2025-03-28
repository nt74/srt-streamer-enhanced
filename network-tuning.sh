#!/bin/bash
# Enhanced SRT Network optimization for DVB streaming with container support

echo "Applying SRT/DVB network optimizations..."

# Function to safely apply sysctl settings
apply_sysctl() {
    param=$1
    value=$2
    param_path="/proc/sys/${param//.//}"

    if [ -f "$param_path" ]; then
        sysctl -w "$param=$value" > /dev/null 2>&1
        echo "✓ Set $param to $value"
    else
        echo "- Skip $param (not available)"
    fi
}

# Network buffer sizes
apply_sysctl "net.core.rmem_max" "26214400"
apply_sysctl "net.core.wmem_max" "26214400"
apply_sysctl "net.core.rmem_default" "4194304"
apply_sysctl "net.core.wmem_default" "4194304"

# UDP specific settings
apply_sysctl "net.ipv4.udp_rmem_min" "8192"
apply_sysctl "net.ipv4.udp_wmem_min" "8192"

# TCP optimizations (for web interface)
apply_sysctl "net.ipv4.tcp_window_scaling" "1"
apply_sysctl "net.ipv4.tcp_timestamps" "1"
apply_sysctl "net.ipv4.tcp_sack" "1"
apply_sysctl "net.ipv4.tcp_fastopen" "3"

# VM settings
apply_sysctl "vm.swappiness" "10"

echo "Network tuning completed with available parameters."
echo "Note: Some kernel parameters may not be available in container environments."
