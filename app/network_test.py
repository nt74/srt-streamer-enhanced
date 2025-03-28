import requests
import json
import subprocess
import time
import logging
import random
import os
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

# Cache settings
CACHE_DURATION = 3600  # 1 hour in seconds
CACHE_FILE = os.path.join(os.path.dirname(__file__), 'data', 'iperf3_servers_cache.json')
SERVER_REPO_URL = "https://raw.githubusercontent.com/R0GGER/public-iperf3-servers/main/servers.json"

class NetworkTester:
    def __init__(self):
        """Initialize the network tester with server list"""
        self.servers = []
        self.last_update = None
        self.load_servers()
        
    def load_servers(self):
        """Load server list from cache or GitHub repo"""
        try:
            # Check if we have a recent cache file
            if os.path.exists(CACHE_FILE):
                cache_age = time.time() - os.path.getmtime(CACHE_FILE)
                if cache_age < CACHE_DURATION:
                    with open(CACHE_FILE, 'r') as f:
                        self.servers = json.load(f)
                        self.last_update = datetime.fromtimestamp(os.path.getmtime(CACHE_FILE))
                        logger.info(f"Loaded {len(self.servers)} servers from cache")
                        return True
            
            # If no cache or outdated, fetch from GitHub
            logger.info("Fetching iperf3 servers from GitHub repo")
            response = requests.get(SERVER_REPO_URL, timeout=15)
            response.raise_for_status()
            
            try:
                server_data = response.json()
                logger.info(f"Successfully parsed server list with {len(server_data)} entries")
                self.servers = server_data
            except json.JSONDecodeError:
                logger.error("Failed to parse server JSON, using fallback servers")
                self.servers = self._get_default_servers()
                return False
            
            self.last_update = datetime.now()
            
            # Save to cache
            os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
            with open(CACHE_FILE, 'w') as f:
                json.dump(self.servers, f)
                
            logger.info(f"Fetched {len(self.servers)} servers from GitHub")
            return True
            
        except Exception as e:
            logger.error(f"Error loading servers: {str(e)}")
            self.servers = self._get_default_servers()
            return False
    
    def _get_default_servers(self):
        """Return optimized default servers focusing on Sweden and Europe"""
        return [
            # Swedish servers
            {
                "location": "Stockholm, Sweden",
                "host": "speedtest.cityhost.se",
                "port": 5201,
                "country": "SE",
                "priority": 1  # Highest priority for Swedish servers
            },
            {
                "location": "Stockholm, Sweden",
                "host": "speedtest.ownit.se",
                "port": 5201,
                "country": "SE",
                "priority": 1
            },
            {
                "location": "Kista, Sweden",
                "host": "speedtest.kamel.network",
                "port": 5201,
                "country": "SE",
                "priority": 1
            },
            
            # High-quality European servers
            {
                "location": "Amsterdam, Netherlands",
                "host": "speedtest.novoserve.com",
                "port": 5201,
                "country": "NL",
                "priority": 2
            },
            {
                "location": "Frankfurt, Germany",
                "host": "speedtest.ip-projects.de",
                "port": 5201,
                "country": "DE",
                "priority": 2
            },
            {
                "location": "Frankfurt, Germany",
                "host": "fra.speedtest.clouvider.net",
                "port": 5201,
                "country": "DE",
                "priority": 2
            },
            {
                "location": "London, United Kingdom",
                "host": "speedtest.lon1.uk.leaseweb.net",
                "port": 5201,
                "country": "GB",
                "priority": 2
            },
            {
                "location": "Paris, France",
                "host": "iperf.online.net",
                "port": 5201,
                "country": "FR",
                "priority": 2
            },
            {
                "location": "Hamburg, Germany",
                "host": "speedtest.wtnet.de",
                "port": 5201,
                "country": "DE",
                "priority": 2
            }
        ]
        
    def get_prioritized_servers(self, limit=10):
        """Return servers prioritized for Swedish/European locations with improved selection"""
        # Categorize servers by location priority
        swedish_servers = [s for s in self.servers if s.get("country") == "SE"]
        
        # European country codes (excluding Sweden)
        european_country_codes = ["DK", "FI", "NO", "DE", "FR", "NL", "GB", "IT", 
                                 "ES", "PL", "CH", "BE", "AT", "IE", "CZ"]
        european_servers = [s for s in self.servers if s.get("country") in european_country_codes]
        
        # Other servers as fallback
        other_servers = [s for s in self.servers if s not in swedish_servers + european_servers]
        
        # Sort each category by priority if available, then randomly
        for server_list in [swedish_servers, european_servers, other_servers]:
            try:
                server_list.sort(key=lambda x: x.get("priority", 99))
            except:
                random.shuffle(server_list)
        
        # Combine with Swedish first, then European, then others
        prioritized = swedish_servers + european_servers + other_servers
        
        logger.info(f"Selected {len(swedish_servers)} Swedish, {len(european_servers)} European servers")
        return prioritized[:limit]
        
    def test_server(self, server, duration=5, bitrate="10M"):
        """Test a single server using iperf3 with enhanced error handling"""
        host = server.get("host")
        port = server.get("port", 5201)
        location = server.get("location", "Unknown location")
        
        logger.info(f"Testing server: {host} ({location})")
        
        # Step 1: Enhanced ping test with timeout and packet count
        try:
            ping_cmd = f"ping -c 4 -i 0.2 -W 2 {host}"
            ping_result = subprocess.run(
                ping_cmd, 
                shell=True, 
                timeout=8,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if ping_result.returncode != 0:
                logger.warning(f"Server {host} not reachable via ping")
                return None
                
            # Parse ping output for RTT stats
            ping_output = ping_result.stdout
            rtt_line = next((line for line in ping_output.split('\n') if "min/avg/max" in line), None)
            if not rtt_line:
                logger.warning(f"Could not parse ping output for {host}")
                return None
                
            rtt_parts = rtt_line.split('=')[1].split('/')
            avg_rtt = float(rtt_parts[1])
            packet_loss = 0  # Default, will be updated from iperf
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Ping test timed out for {host}")
            return None
        except Exception as e:
            logger.warning(f"Ping test failed for {host}: {str(e)}")
            return None
            
        # Step 2: Run iperf3 test with enhanced parameters
        try:
            iperf_cmd = [
                "iperf3",
                "-c", host,
                "-p", str(port),
                "-u",  # UDP protocol
                "-b", bitrate,
                "-t", str(duration),
                "-J",  # JSON output
                "--connect-timeout", "3000",  # 3 second connection timeout
                "--bandwidth", bitrate,
                "--length", "1200"  # Typical SRT packet size
            ]
            
            result = subprocess.run(
                iperf_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=duration + 10,  # Extra time for connection setup
                text=True
            )
            
            if result.returncode != 0:
                error_msg = result.stderr[:200] if result.stderr else "Unknown error"
                logger.warning(f"iperf3 test failed for {host}: {error_msg}")
                return None
                
            # Parse JSON output with enhanced error handling
            try:
                data = json.loads(result.stdout)
                
                # Extract key metrics with fallbacks
                end_data = data.get('end', {}).get('sum', {})
                packets_sent = end_data.get('packets', 0)
                lost_packets = end_data.get('lost_packets', 0)
                jitter_ms = end_data.get('jitter_ms', 0)
                
                if packets_sent == 0:
                    logger.warning(f"No packets sent in test to {host}")
                    return None
                
                # Calculate loss percentage
                loss_percent = (lost_packets / packets_sent) * 100 if packets_sent > 0 else 0
                
                # Calculate SRT parameters with the actual measured RTT
                srt_latency = self._calculate_srt_latency(avg_rtt, loss_percent)
                overhead = self._calculate_overhead(loss_percent)
                
                logger.info(
                    f"Test results for {host}: "
                    f"RTT={avg_rtt:.2f}ms, "
                    f"Loss={loss_percent:.2f}%, "
                    f"Jitter={jitter_ms:.2f}ms, "
                    f"Recommended Latency={srt_latency}ms, "
                    f"Overhead={overhead}%"
                )
                
                return {
                    "server": host,
                    "server_location": location,
                    "country": server.get("country", "Unknown"),
                    "rtt_ms": avg_rtt,
                    "loss_percent": loss_percent,
                    "jitter_ms": jitter_ms,
                    "latency_recommendation": srt_latency,
                    "overhead_recommendation": overhead,
                    "rtt_multiplier": self._get_rtt_multiplier(loss_percent),
                    "test_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "test_duration": duration,
                    "bitrate": bitrate
                }
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse iperf3 output for {host}: {str(e)}")
                return None
            except KeyError as e:
                logger.error(f"Missing expected data in iperf3 output for {host}: {str(e)}")
                return None
                
        except subprocess.TimeoutExpired as e:
            logger.error(f"iperf3 test timed out for {host}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"iperf3 test failed for {host}: {str(e)}")
            return None
    
    def run_network_test(self, target=None, duration=5, bitrate="10M"):
        """Run network test using the best available server with enhanced logic"""
        # Validate parameters
        duration = min(max(duration, 3), 10)  # Clamp between 3-10 seconds
        bitrate = bitrate if bitrate in ["5M", "10M", "20M", "50M"] else "10M"
        
        # If target specified, test only that server
        if target:
            server = {
                "host": target, 
                "port": 5201, 
                "location": "User-specified server",
                "country": "Custom"
            }
            result = self.test_server(server, duration, bitrate)
            if result:
                logger.info(f"Successfully tested user-provided server: {target}")
                return result
            else:
                logger.warning(f"Test failed with specified server {target}, will try automatic selection")
        
        # Get prioritized servers (focus on Sweden and Europe)
        servers = self.get_prioritized_servers(limit=6)  # Test fewer but better servers
        
        # Test servers with early exit if we find a good one
        results = []
        for server in servers:
            result = self.test_server(server, duration, bitrate)
            if result:
                results.append(result)
                
                # Early exit if we find an excellent server
                if result['loss_percent'] <= 1.0 and result['rtt_ms'] <= 50:
                    logger.info(f"Found excellent server: {result['server']}")
                    break
                    
                # Or if we have enough decent results
                if len(results) >= 3:
                    break
        
        # Return best result based on combined metrics
        if results:
            # Score each result (lower is better)
            for result in results:
                # Weighted score considering both latency and packet loss
                latency_score = result['rtt_ms'] / 100  # Normalize
                loss_score = result['loss_percent'] / 5  # Normalize
                result['score'] = (latency_score * 0.6) + (loss_score * 0.4)
            
            # Sort by score and return the best one
            results.sort(key=lambda x: x['score'])
            best_result = results[0]
            
            logger.info(
                f"Selected best server: {best_result['server']} "
                f"(Score: {best_result['score']:.2f}, "
                f"RTT: {best_result['rtt_ms']:.2f}ms, "
                f"Loss: {best_result['loss_percent']:.2f}%)"
            )
            return best_result
        else:
            logger.warning("All server tests failed, using fallback values")
            return self._get_fallback_result()
    
    def _get_fallback_result(self):
        """Return conservative fallback values when all tests fail"""
        return {
            "server": "none",
            "server_location": "Fallback values",
            "country": "None",
            "rtt_ms": 50,
            "loss_percent": 2.0,
            "jitter_ms": 5.0,
            "latency_recommendation": 150,
            "overhead_recommendation": 25,
            "rtt_multiplier": 4,
            "test_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "error": "All servers failed",
            "bitrate": "10M"
        }
    
    def _calculate_srt_latency(self, rtt, loss_percent):
        """Calculate recommended SRT latency based on Haivision formula"""
        # Ensure minimum RTT value
        rtt = max(rtt, 20)  # SRT minimum response time
        
        # Get multiplier based on loss percentage
        multiplier = self._get_rtt_multiplier(loss_percent)
        min_latency = self._get_min_latency(loss_percent)
            
        # Calculate and apply minimum
        calculated = round(multiplier * rtt)
        return max(calculated, min_latency)
    
    def _get_rtt_multiplier(self, loss_percent):
        """Get RTT multiplier based on loss percentage"""
        if loss_percent <= 1.0:
            return 3  # Excellent conditions
        elif loss_percent <= 3.0:
            return 4  # Good conditions
        elif loss_percent <= 7.0:
            return 5  # Moderate conditions
        elif loss_percent <= 10.0:
            return 6  # Poor conditions
        else:
            return 7  # Very poor conditions
    
    def _get_min_latency(self, loss_percent):
        """Get minimum latency based on loss percentage"""
        if loss_percent <= 1.0:
            return 60  # Excellent conditions
        elif loss_percent <= 3.0:
            return 80  # Good conditions
        elif loss_percent <= 7.0:
            return 100  # Moderate conditions
        elif loss_percent <= 10.0:
            return 120  # Poor conditions
        else:
            return 150  # Very poor conditions
    
    def _calculate_overhead(self, loss_percent):
        """Calculate recommended overhead based on Haivision standards"""
        if loss_percent <= 1.0:
            return 25  # Excellent conditions
        elif loss_percent <= 3.0:
            return 20  # Good conditions
        elif loss_percent <= 7.0:
            return 15  # Moderate conditions
        elif loss_percent <= 10.0:
            return 10  # Poor conditions
        else:
            return 25  # Very poor conditions (higher overhead to compensate)
