#!/bin/bash
# SRT Streamer Enhanced Startup Script

# Set working directory
cd /opt/srt-streamer-enhanced

# Start network tuning
echo "Starting network tuning..."
echo "Applying SRT/DVB network optimizations..."

# Attempt to set network parameters, skipping unavailable ones
if sysctl -w net.core.rmem_max=26214400 &>/dev/null; then
    echo "✓ Set net.core.rmem_max to 26214400"
else
    echo "- Skip net.core.rmem_max (not available)"
fi

if sysctl -w net.core.wmem_max=26214400 &>/dev/null; then
    echo "✓ Set net.core.wmem_max to 26214400"
else
    echo "- Skip net.core.wmem_max (not available)"
fi

if sysctl -w net.core.rmem_default=8388608 &>/dev/null; then
    echo "✓ Set net.core.rmem_default to 8388608"
else
    echo "- Skip net.core.rmem_default (not available)"
fi

if sysctl -w net.core.wmem_default=8388608 &>/dev/null; then
    echo "✓ Set net.core.wmem_default to 8388608"
else
    echo "- Skip net.core.wmem_default (not available)"
fi

if sysctl -w net.ipv4.udp_rmem_min=8192 &>/dev/null; then
    echo "✓ Set net.ipv4.udp_rmem_min to 8192"
fi

if sysctl -w net.ipv4.udp_wmem_min=8192 &>/dev/null; then
    echo "✓ Set net.ipv4.udp_wmem_min to 8192"
fi

if sysctl -w net.ipv4.tcp_window_scaling=1 &>/dev/null; then
    echo "✓ Set net.ipv4.tcp_window_scaling to 1"
fi

if sysctl -w net.ipv4.tcp_timestamps=1 &>/dev/null; then
    echo "✓ Set net.ipv4.tcp_timestamps to 1"
fi

if sysctl -w net.ipv4.tcp_sack=1 &>/dev/null; then
    echo "✓ Set net.ipv4.tcp_sack to 1"
fi

if sysctl -w net.ipv4.tcp_fastopen=3 &>/dev/null; then
    echo "✓ Set net.ipv4.tcp_fastopen to 3"
fi

if sysctl -w vm.swappiness=10 &>/dev/null; then
    echo "✓ Set vm.swappiness to 10"
fi

echo "Network tuning completed with available parameters."
echo "Note: Some kernel parameters may not be available in container environments."

# Create data directory if it doesn't exist
mkdir -p /opt/srt-streamer-enhanced/app/data

# Update external IP - now using the app's data directory
echo "Updating external IP..."
echo "Trying https://ipinfo.io/ip..."
curl -s https://ipinfo.io/ip > /opt/srt-streamer-enhanced/app/data/external_ip.txt || echo "unknown" > /opt/srt-streamer-enhanced/app/data/external_ip.txt
echo "Found external IP: $(cat /opt/srt-streamer-enhanced/app/data/external_ip.txt)"

# Activate virtual environment and start application
echo "Starting SRT Streamer Enhanced..."
source /opt/venv/bin/activate
cd /opt/srt-streamer-enhanced
export HOST=127.0.0.1
export PORT=5000
export THREADS=8
export MEDIA_FOLDER=/opt/srt-streamer-enhanced/media
python wsgi.py
