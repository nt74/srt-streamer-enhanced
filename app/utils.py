import psutil
import os
import subprocess
import requests
from datetime import datetime
import logging
import time
import json

logger = logging.getLogger(__name__)

# Define paths for external IP cache
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
EXTERNAL_IP_FILE = os.path.join(DATA_DIR, 'external_ip.txt')
EXTERNAL_IP_CACHE_FILE = os.path.join(DATA_DIR, 'external_ip_cache.json')

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

def format_size(bytes_value, suffix="B"):
    """Format bytes to human-readable format"""
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(bytes_value) < 1024.0:
            return f"{bytes_value:.2f} {unit}{suffix}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} Y{suffix}"

def get_current_username():
    """Get the authenticated username"""
    # Return the authenticated user (mcradmin) instead of system user
    return "mcradmin"

def get_external_ip():
    """Get external IP address with enhanced caching and multiple fallback methods"""
    # First try to load from cache if recent
    cached_ip = _load_cached_ip()
    if cached_ip:
        return cached_ip

    ip = "unknown"
    services = [
        "https://api.ipify.org",  # Simple and reliable
        "https://ipinfo.io/ip",   # Popular service
        "https://icanhazip.com",   # Simple service
        "https://ifconfig.me/ip",  # Another reliable option
        "https://checkip.amazonaws.com"  # Amazon's service
    ]

    # Try each service until we get a valid IP
    for service in services:
        try:
            logger.info(f"Trying to fetch external IP from {service}")
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                ip = response.text.strip()
                if _is_valid_ip(ip):
                    # Cache the successful result
                    _cache_ip(ip)
                    return ip
        except Exception as e:
            logger.warning(f"Failed to fetch IP from {service}: {e}")
            continue

    # If all services fail, try command line methods
    ip = _try_command_line_methods()
    if ip != "unknown":
        _cache_ip(ip)
        return ip

    # Final fallback to cached value even if expired
    return cached_ip or ip

def _is_valid_ip(ip_str):
    """Basic validation of IP address format"""
    if not ip_str:
        return False
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def _load_cached_ip():
    """Load cached IP address if recent enough"""
    try:
        # First try JSON cache with timestamp
        if os.path.exists(EXTERNAL_IP_CACHE_FILE):
            with open(EXTERNAL_IP_CACHE_FILE, 'r') as f:
                cache = json.load(f)
                if time.time() - cache['timestamp'] < 3600:  # 1 hour cache
                    return cache['ip']

        # Fallback to plain text file
        if os.path.exists(EXTERNAL_IP_FILE):
            file_age = time.time() - os.path.getmtime(EXTERNAL_IP_FILE)
            if file_age < 3600:  # 1 hour cache
                with open(EXTERNAL_IP_FILE, 'r') as f:
                    ip = f.read().strip()
                    if ip and _is_valid_ip(ip):
                        return ip
    except Exception as e:
        logger.warning(f"Failed to read cached IP: {e}")
    return None

def _cache_ip(ip):
    """Cache the IP address with timestamp"""
    try:
        # Save to JSON cache with timestamp
        cache_data = {
            'ip': ip,
            'timestamp': time.time()
        }
        with open(EXTERNAL_IP_CACHE_FILE, 'w') as f:
            json.dump(cache_data, f)

        # Also save to plain text file for backward compatibility
        with open(EXTERNAL_IP_FILE, 'w') as f:
            f.write(ip)
    except Exception as e:
        logger.warning(f"Couldn't write IP to cache: {e}")

def _try_command_line_methods():
    """Try various command line methods to get external IP"""
    methods = [
        "dig +short myip.opendns.com @resolver1.opendns.com",
        "curl -s ifconfig.me",
        "curl -s icanhazip.com",
        "curl -s ipinfo.io/ip"
    ]

    for cmd in methods:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            ip = result.stdout.strip()
            if ip and _is_valid_ip(ip):
                return ip
        except Exception as e:
            logger.debug(f"Command {cmd} failed: {e}")
            continue

    return "unknown"

def get_system_info():
    """Get comprehensive system information"""
    # Get external IP with caching
    external_ip = get_external_ip()
    
    # Get current user
    current_user = get_current_username()
    
    # Current UTC time
    current_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    
    # Get CPU usage
    try:
        cpu_usage = round(psutil.cpu_percent(interval=1))
    except Exception as e:
        logger.warning(f"Couldn't get CPU usage: {e}")
        cpu_usage = 0

    # Get memory information
    try:
        mem = psutil.virtual_memory()
        memory_total = format_size(mem.total)
        memory_used = format_size(mem.used)
        memory_percent = round(mem.percent)
    except Exception as e:
        logger.warning(f"Couldn't get memory info: {e}")
        memory_total = memory_used = "N/A"
        memory_percent = 0

    # Get disk information
    try:
        disk = psutil.disk_usage("/")
        disk_total = format_size(disk.total)
        disk_used = format_size(disk.used)
        disk_percent = round(disk.percent)
    except Exception as e:
        logger.warning(f"Couldn't get disk info: {e}")
        disk_total = disk_used = "N/A"
        disk_percent = 0

    # Get network information
    try:
        net_io = psutil.net_io_counters()
        net_info = {
            'bytes_sent': format_size(net_io.bytes_sent),
            'bytes_recv': format_size(net_io.bytes_recv),
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }
    except Exception as e:
        logger.warning(f"Couldn't get network info: {e}")
        net_info = {}

    # Get system uptime
    try:
        uptime_seconds = time.time() - psutil.boot_time()
        uptime = str(datetime.utcfromtimestamp(uptime_seconds).strftime("%H:%M:%S"))
    except Exception as e:
        logger.warning(f"Couldn't get uptime: {e}")
        uptime = "N/A"

    # Compile all information
    info = {
        "cpu_usage": cpu_usage,
        "memory_total": memory_total,
        "memory_used": memory_used,
        "memory_percent": memory_percent,
        "disk_total": disk_total,
        "disk_used": disk_used,
        "disk_percent": disk_percent,
        "external_ip": external_ip,
        "utc_time": current_utc,
        "current_user": current_user,
        "uptime": uptime,
        "network": net_info
    }
    
    return info

def check_disk_space(path="/", min_gb=5):
    """Check if there's enough disk space available"""
    try:
        stat = psutil.disk_usage(path)
        free_gb = stat.free / (1024 ** 3)  # Convert to GB
        return free_gb >= min_gb
    except Exception as e:
        logger.error(f"Error checking disk space: {e}")
        return False

def get_system_load():
    """Get system load averages"""
    try:
        load_avg = os.getloadavg()
        return {
            "1min": load_avg[0],
            "5min": load_avg[1],
            "15min": load_avg[2]
        }
    except Exception as e:
        logger.error(f"Error getting system load: {e}")
        return None
