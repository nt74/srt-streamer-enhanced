#!/bin/bash
# Script to get external IP address

# Try multiple services in case one is down
SERVICES=(
    "https://ipinfo.io/ip"
    "https://api.ipify.org"
    "https://icanhazip.com"
)

for SERVICE in "${SERVICES[@]}"; do
    echo "Trying $SERVICE..."
    EXTERNAL_IP=$(curl -s --connect-timeout 5 "$SERVICE")
    
    # Validate IP format (simple regex)
    if [[ $EXTERNAL_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Found external IP: $EXTERNAL_IP"
        echo "{\"ip\":\"$EXTERNAL_IP\",\"updated\":\"$(date -u +"%Y-%m-%d %H:%M:%S UTC")\"}" > external_ip.json
        exit 0
    fi
done

echo "Failed to get external IP from any service"
echo "{\"ip\":null,\"updated\":\"$(date -u +"%Y-%m-%d %H:%M:%S UTC")\"}" > external_ip.json
exit 1
