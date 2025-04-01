# /opt/srt-streamer-enhanced/app/network_test.py
# Complete script with TCP fallback for high RTT tests

import os
import json
import requests
import subprocess
import random
import time
from datetime import datetime, timedelta
import logging
import re

logger = logging.getLogger(__name__)

# --- Constants ---
IPERF_JSON_URL = "https://export.iperf3serverlist.net/json.php?action=download"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, 'data')
IPERF_JSON_PATH = os.path.join(DATA_DIR, 'iperf3_export_servers.json')
EXTERNAL_IP_FILE_PATH = os.path.join(DATA_DIR, 'external_ip.txt')
GEOIP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,continentCode,continent,countryCode,country,query"
DEFAULT_IPERF_PORT = 5201
DOWNLOAD_CACHE_DURATION = timedelta(hours=6)
PING_COUNT = 4
IPERF_UDP_DURATION = 5          # Default duration for UDP tests (low RTT)
IPERF_DEFAULT_UDP_BITRATE = "10M" # Default bitrate for UDP tests (low RTT)
IPERF_TCP_DURATION = 7          # Slightly longer duration for TCP tests maybe
IPERF_PACKET_LENGTH = 1200      # For UDP tests
IPERF_SUBPROCESS_TIMEOUT = 35   # Generous overall timeout allowing for TCP test time
RTT_THRESHOLD_FOR_TCP_FALLBACK = 250 # Switch to TCP iperf3 if RTT(ms) is above this
ASSUMED_LOSS_FOR_TCP_FALLBACK = 7.0 # Assume 7% loss when only RTT is known

os.makedirs(DATA_DIR, exist_ok=True)

class NetworkTester:
    def __init__(self):
        self.servers = []
        self.load_servers()

    # --- _download_iperf_list, _parse_host_port, load_servers ---
    # --- get_server_regions, get_external_ip_and_location ---
    # --- run_ping, calculate_srt_settings, get_fallback_results ---
    # (Keep these methods exactly as they were in the previous full script response)
    def _download_iperf_list(self, force_update=False):
        needs_download = force_update
        if not os.path.exists(IPERF_JSON_PATH): logger.info(f"Cache file not found: {IPERF_JSON_PATH}. Downloading."); needs_download = True
        else:
            try:
                file_mod_time = datetime.fromtimestamp(os.path.getmtime(IPERF_JSON_PATH))
                if datetime.now() - file_mod_time > DOWNLOAD_CACHE_DURATION: logger.info("Cache file outdated. Downloading."); needs_download = True
                else: logger.debug("Using cached iperf3 server list."); return False
            except Exception as e: logger.warning(f"Could not check cache file age for {IPERF_JSON_PATH}: {e}. Will attempt download."); needs_download = True
        if needs_download:
            logger.info(f"Fetching iperf3 server list from {IPERF_JSON_URL}...")
            try:
                response = requests.get(IPERF_JSON_URL, timeout=30, stream=True); response.raise_for_status()
                content = b""; first_chunk = True; looks_like_json = False
                for chunk in response.iter_content(chunk_size=8192):
                     if first_chunk:
                          if chunk.strip().startswith(b'['): looks_like_json = True
                          first_chunk = False
                     content += chunk
                if not looks_like_json or not content.strip().endswith(b']'):
                     try: error_hint = content.decode('utf-8', errors='ignore')[:200]
                     except Exception: error_hint = "(Could not decode non-JSON response)"
                     raise ValueError(f"Downloaded content does not appear to be a JSON array. Starts with: {error_hint}")
                json.loads(content) # Validate
                with open(IPERF_JSON_PATH, 'wb') as f: f.write(content)
                logger.info(f"Download successful, saved to {IPERF_JSON_PATH}.")
                return True
            except requests.exceptions.RequestException as e: logger.error(f"Error downloading iperf3 server list: {e}"); return True
            except (json.JSONDecodeError, ValueError) as e:
                 logger.error(f"Downloaded content is not valid JSON or structure is wrong: {e}")
                 if os.path.exists(IPERF_JSON_PATH):
                     try: os.remove(IPERF_JSON_PATH)
                     except Exception as rm_e: logger.warning(f"Could not remove potentially invalid cache file {IPERF_JSON_PATH}: {rm_e}")
                 return True
            except Exception as e: logger.error(f"Unexpected error during iperf list download: {e}", exc_info=True); return True
        else: return False

    def _parse_host_port(self, server_entry):
        ip_host_string = server_entry.get("IP_HOST", "");
        if not ip_host_string: return None, None
        parts = ip_host_string.split(); host = None; port = DEFAULT_IPERF_PORT; port_str = None
        try:
            if '-c' in parts: c_index = parts.index('-c'); host = parts[c_index + 1] if c_index + 1 < len(parts) else None
            if not host: logger.warning(f"Could not find host after '-c' in: {ip_host_string}"); return None, None
            if '-p' in parts: p_index = parts.index('-p'); port_str = parts[p_index + 1] if p_index + 1 < len(parts) else None
            if port_str:
                port_str = port_str.strip()
                if '-' in port_str: base_port_str = port_str.split('-')[0].strip(); port = int(base_port_str) if base_port_str.isdigit() else DEFAULT_IPERF_PORT
                elif port_str.isdigit(): port = int(port_str)
                else: logger.warning(f"Non-standard port format '{port_str}', using default."); port = DEFAULT_IPERF_PORT
        except (ValueError, IndexError) as e: logger.error(f"Error parsing IP_HOST string '{ip_host_string}': {e}"); return None, None
        if not host or len(host) < 3: logger.warning(f"Extracted host '{host}' seems invalid from: {ip_host_string}"); return None, None
        return host, port

    def load_servers(self):
        logger.info("Attempting to load/update iperf3 server list...")
        self._download_iperf_list()
        processed_servers = [];
        if not os.path.exists(IPERF_JSON_PATH): logger.error(f"Server list file unavailable: {IPERF_JSON_PATH}"); self.servers = []; return
        try:
            with open(IPERF_JSON_PATH, 'r', encoding='utf-8') as f:
                try: raw_servers = json.load(f)
                except json.JSONDecodeError as json_err: logger.error(f"JSON Decode Error in {IPERF_JSON_PATH}: {json_err}."); raw_servers = []
            if not isinstance(raw_servers, list): logger.error(f"Loaded server data is not a list."); raw_servers = []
            logger.info(f"Loaded {len(raw_servers)} raw server entries.")
            count_parsed = 0
            for index, raw_server in enumerate(raw_servers):
                 if not isinstance(raw_server, dict): logger.warning(f"Skipping non-dictionary entry at index {index}."); continue
                 host, port = self._parse_host_port(raw_server)
                 if host and port:
                     continent = raw_server.get('CONTINENT')
                     if not continent: logger.debug(f"Skipping server with missing CONTINENT: {host}"); continue
                     processed_servers.append({'host': host, 'port': port, 'site': raw_server.get('SITE', 'N/A'), 'country': raw_server.get('COUNTRY'), 'continent': continent, 'provider': raw_server.get('PROVIDER'), 'options_str': raw_server.get('OPTIONS')})
                     count_parsed += 1
                 else: logger.debug(f"Skipping entry due to parsing failure: {raw_server.get('IP_HOST', 'N/A')}")
            logger.info(f"Successfully processed {count_parsed} servers with continent info.")
            self.servers = processed_servers
        except FileNotFoundError: logger.error(f"Server list file not found: {IPERF_JSON_PATH}"); self.servers = []
        except Exception as e: logger.error(f"Unexpected error loading servers: {e}", exc_info=True); self.servers = []

    def get_server_regions(self):
        if not self.servers: self.load_servers()
        continents = set(server.get('continent') for server in self.servers if server.get('continent'))
        return sorted(list(continents))

    def get_external_ip_and_location(self):
        ip_address = None; ip_source = "Unknown"
        try:
            logger.debug(f"Attempting to read external IP from: {EXTERNAL_IP_FILE_PATH}")
            if os.path.exists(EXTERNAL_IP_FILE_PATH):
                with open(EXTERNAL_IP_FILE_PATH, 'r', encoding='utf-8') as f: ip_address = f.readline().strip()
                if not ip_address: logger.warning(f"External IP file empty."); return {'ip': None, 'error': 'Local IP file is empty'}
                ip_source = f"file ({EXTERNAL_IP_FILE_PATH})"
                logger.info(f"Read external IP from {ip_source}: {ip_address}")
            else: logger.warning(f"External IP file not found."); return {'ip': None, 'error': 'Local IP file not found'}
        except Exception as e: logger.error(f"Error reading external IP file: {e}", exc_info=True); return {'ip': None, 'error': f'Error reading local IP file'}
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address): logger.warning(f"Invalid IP format in file: {ip_address}"); return {'ip': ip_address, 'error': 'Invalid IP format in local file'}
        api_url = GEOIP_API_URL.format(ip=ip_address); logger.info(f"Looking up GeoIP for {ip_address} via {api_url}")
        try:
            response = requests.get(api_url, timeout=7); response.raise_for_status(); data = response.json()
            if data.get('status') == 'success':
                location_info = {'ip': data.get('query', ip_address), 'continent': data.get('continent'), 'continentCode': data.get('continentCode'), 'country': data.get('country'), 'countryCode': data.get('countryCode'), 'error': None }; logger.info(f"GeoIP Result: {location_info}"); return location_info
            else: api_msg = data.get('message', 'API Error'); logger.warning(f"GeoIP API Error for {ip_address}: {api_msg}"); return {'ip': ip_address, 'error': api_msg}
        except requests.exceptions.Timeout: logger.error(f"GeoIP API call timed out"); return {'ip': ip_address, 'error': 'GeoIP API Timeout'}
        except requests.exceptions.RequestException as e: logger.error(f"Error calling GeoIP API: {e}"); return {'ip': ip_address, 'error': f"GeoIP Network Error"}
        except json.JSONDecodeError as e: logger.error(f"Error decoding GeoIP API response: {e}"); return {'ip': ip_address, 'error': 'Invalid GeoIP Response'}
        except Exception as e: logger.error(f"Unexpected error in GeoIP lookup: {e}", exc_info=True); return {'ip': ip_address, 'error': 'GeoIP Internal Error'}

    def run_ping(self, host):
        command = ['ping', '-c', str(PING_COUNT), '-i', '0.2', '-W', '2', host]; logger.info(f"Running: {' '.join(command)}")
        try:
            env = os.environ.copy(); env['LANG'] = 'C'; result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False, env=env)
            if result.returncode != 0: logger.warning(f"Ping failed for {host}. Code: {result.returncode}."); return None
            avg_rtt = None; pattern_linux = r'min/avg/max/mdev\s*=\s*[\d.]+/([\d.]+)/'; pattern_macos = r'min/avg/max/stddev\s*=\s*[\d.]+/([\d.]+)/'; # Simplified regex slightly
            match_linux = re.search(pattern_linux, result.stdout, re.IGNORECASE | re.MULTILINE); match_macos = re.search(pattern_macos, result.stdout, re.IGNORECASE | re.MULTILINE)
            avg_rtt_str = None
            if match_linux: avg_rtt_str = match_linux.group(1); logger.debug(f"Parsed Linux style ping for {host}")
            elif match_macos: avg_rtt_str = match_macos.group(1); logger.debug(f"Parsed MacOS style ping for {host}")
            if avg_rtt_str:
                try: avg_rtt = float(avg_rtt_str)
                except ValueError: logger.warning(f"Could not convert RTT '{avg_rtt_str}' to float for {host}"); avg_rtt = None
            if avg_rtt is not None: logger.info(f"Ping Avg RTT for {host}: {avg_rtt:.2f} ms"); return avg_rtt
            else: logger.warning(f"Could not parse ping avg RTT for {host}."); return None
        except subprocess.TimeoutExpired: logger.warning(f"Ping timed out for {host}"); return None
        except FileNotFoundError: logger.error(f"'ping' command not found."); return None
        except Exception as e: logger.error(f"Error processing ping for {host}: {e}", exc_info=True); return None

    def run_iperf3_udp(self, host, port, bitrate=IPERF_DEFAULT_UDP_BITRATE, duration=IPERF_UDP_DURATION):
        """Runs iperf3 UDP test (only called if RTT is low). Returns dict with results or {'error': ...}."""
        timeout_seconds = duration + 25 # Keep generous timeout
        iperf_cmd = ["iperf3", "-c", host, "-p", str(port), "-u", "-b", bitrate, "-t", str(duration), "-J", "--length", str(IPERF_PACKET_LENGTH), "--connect-timeout", "5000"]
        logger.info(f"Running UDP iperf3: {' '.join(iperf_cmd)}")
        try:
            result = subprocess.run(iperf_cmd, capture_output=True, text=True, timeout=timeout_seconds, check=False)
            iperf_data = None; parse_error = None
            try:
                 iperf_data = json.loads(result.stdout)
                 if isinstance(iperf_data, dict) and 'error' in iperf_data: logger.warning(f"iperf3 UDP test for {host}:{port} returned JSON error: {iperf_data['error']}"); return {'type': 'UDP', 'error': iperf_data['error']}
            except json.JSONDecodeError as e: parse_error = e
            if parse_error or result.returncode != 0:
                 stderr_msg = result.stderr.strip() if result.stderr else "(No stderr)"; stdout_sample = result.stdout.strip()[:200] if result.stdout else "(No stdout)"
                 log_msg = f"iperf3 UDP failed for {host}:{port}. Code: {result.returncode}. ";
                 if parse_error: log_msg += f"JSON Parse Error: {parse_error}. "
                 log_msg += f"Stderr: {stderr_msg}. Stdout Sample: {stdout_sample}"; logger.warning(log_msg)
                 if "connection refused" in stderr_msg.lower(): return {'type': 'UDP', 'error': 'Connection refused'}
                 if "unable to connect" in stderr_msg.lower(): return {'type': 'UDP', 'error': 'Server unreachable'}
                 if "interrupt" in stderr_msg.lower(): return {'type': 'UDP', 'error': 'Test interrupted'}
                 if "parameter" in stderr_msg.lower(): return {'type': 'UDP', 'error': 'Invalid iperf3 parameter'}
                 return {'type': 'UDP', 'error': f'Test command failed (code {result.returncode})' if result.returncode !=0 else 'Invalid JSON output'}
            summary = iperf_data.get('end', {}).get('sum', {}); jitter_ms = summary.get('jitter_ms'); lost_packets = summary.get('lost_packets'); total_packets = summary.get('packets'); bandwidth_bps = summary.get('bits_per_second')
            if total_packets is None or jitter_ms is None or lost_packets is None or bandwidth_bps is None: error_msg = "Missing key UDP metrics in iperf3 JSON output"; logger.error(f"{error_msg} for {host}:{port}. Data: {summary}"); return {'type': 'UDP', 'error': error_msg}
            loss_percent = (lost_packets / total_packets) * 100 if total_packets > 0 else 0
            bandwidth_mbps = bandwidth_bps / 1_000_000 if bandwidth_bps is not None else None
            results = {'type': 'UDP', 'bandwidth_mbps': f"{bandwidth_mbps:.2f}" if bandwidth_mbps is not None else None, 'loss_percent': f"{loss_percent:.2f}" if loss_percent is not None else None, 'jitter_ms': f"{jitter_ms:.2f}" if jitter_ms is not None else None, 'error': None }
            logger.info(f"UDP iperf3 results for {host}:{port}: BW={results['bandwidth_mbps']} Mbps, Loss={results['loss_percent']}%, Jitter={results['jitter_ms']}ms"); return results
        except subprocess.TimeoutExpired: logger.error(f"iperf3 UDP test timed out (>{timeout_seconds}s) for {host}:{port}"); return {'type': 'UDP', 'error': 'Test timed out'}
        except FileNotFoundError: logger.error(f"'iperf3' command not found."); return {'type': 'UDP', 'error': 'iperf3 command not found'}
        except Exception as e: logger.error(f"iperf3 UDP test failed for {host}:{port}: {e}", exc_info=True); return {'type': 'UDP', 'error': f'Test execution error: {e}'}

    # --- NEW: Method to run TCP iperf3 test ---
    def run_iperf3_tcp(self, host, port, duration=IPERF_TCP_DURATION):
        """Runs iperf3 TCP test (-R), returns dict with results or {'error': ...}."""
        timeout_seconds = duration + 25 # Generous overall timeout
        iperf_cmd = ["iperf3", "-c", host, "-p", str(port), "-R", "-t", str(duration), "-J", "--connect-timeout", "5000"]
        logger.info(f"Running TCP iperf3 (-R): {' '.join(iperf_cmd)}")
        try:
            result = subprocess.run(iperf_cmd, capture_output=True, text=True, timeout=timeout_seconds, check=False)
            iperf_data = None; parse_error = None
            try:
                 iperf_data = json.loads(result.stdout)
                 if isinstance(iperf_data, dict) and 'error' in iperf_data: logger.warning(f"iperf3 TCP test for {host}:{port} returned JSON error: {iperf_data['error']}"); return {'type': 'TCP', 'error': iperf_data['error']}
            except json.JSONDecodeError as e: parse_error = e
            if parse_error or result.returncode != 0:
                 stderr_msg = result.stderr.strip() if result.stderr else "(No stderr)"; stdout_sample = result.stdout.strip()[:200] if result.stdout else "(No stdout)"
                 log_msg = f"iperf3 TCP failed for {host}:{port}. Code: {result.returncode}. ";
                 if parse_error: log_msg += f"JSON Parse Error: {parse_error}. "
                 log_msg += f"Stderr: {stderr_msg}. Stdout Sample: {stdout_sample}"; logger.warning(log_msg)
                 if "connection refused" in stderr_msg.lower(): return {'type': 'TCP', 'error': 'Connection refused'}
                 if "unable to connect" in stderr_msg.lower(): return {'type': 'TCP', 'error': 'Server unreachable'}
                 return {'type': 'TCP', 'error': f'Test command failed (code {result.returncode})' if result.returncode !=0 else 'Invalid JSON output'}

            # For TCP -R, look in 'end' -> 'sum_received'
            summary = iperf_data.get('end', {}).get('sum_received', {})
            bandwidth_bps = summary.get('bits_per_second')
            retransmits = summary.get('retransmits') # May be useful info

            if bandwidth_bps is None: error_msg = "Missing key TCP bandwidth metric in iperf3 JSON output"; logger.error(f"{error_msg} for {host}:{port}. Data: {summary}"); return {'type': 'TCP', 'error': error_msg}

            bandwidth_mbps = bandwidth_bps / 1_000_000

            results = {'type': 'TCP', 'bandwidth_mbps': f"{bandwidth_mbps:.2f}", 'retransmits': retransmits, 'loss_percent': None, 'jitter_ms': None, 'error': None } # Note: loss/jitter are None for TCP
            logger.info(f"TCP iperf3 results for {host}:{port}: BW={results['bandwidth_mbps']} Mbps, Retransmits={retransmits}")
            return results

        except subprocess.TimeoutExpired: logger.error(f"iperf3 TCP test timed out (>{timeout_seconds}s) for {host}:{port}"); return {'type': 'TCP', 'error': 'Test timed out'}
        except FileNotFoundError: logger.error(f"'iperf3' command not found."); return {'type': 'TCP', 'error': 'iperf3 command not found'}
        except Exception as e: logger.error(f"iperf3 TCP test failed for {host}:{port}: {e}", exc_info=True); return {'type': 'TCP', 'error': f'Test execution error: {e}'}


    def calculate_srt_settings(self, rtt, loss_percent):
        """Calculates recommended SRT settings based STRICTLY on Haivision table."""
        # --- This method remains unchanged, using RTT and UDP loss % ---
        if rtt is None or loss_percent is None: logger.warning("Cannot calculate SRT settings: Missing RTT or Loss data."); return None
        rtt = max(1.0, float(rtt)); loss = max(0.0, min(float(loss_percent), 100.0))
        if loss <= 1.0:     multiplier, overhead = 3, 1
        elif loss <= 3.0:   multiplier, overhead = 4, 4
        elif loss <= 7.0:   multiplier, overhead = 6, 9
        elif loss <= 10.0:  multiplier, overhead = 8, 15
        elif loss <= 12.0:  multiplier, overhead = 8, 20
        elif loss <= 20.0:  multiplier, overhead = 10, 38
        elif loss <= 25.0:  multiplier, overhead = 13, 46
        elif loss <= 27.0:  multiplier, overhead = 14, 50
        elif loss <= 30.0:  multiplier, overhead = 14, 61
        elif loss <= 40.0:  multiplier, overhead = 30, 97
        else: multiplier, overhead = 30, 97; logger.warning(f"High packet loss ({loss:.1f}%) detected.")
        recommended_latency = max(round(multiplier * rtt), 80)
        results = {'rtt_multiplier': multiplier, 'overhead_percent': overhead, 'latency_ms': recommended_latency}
        logger.info(f"Calculated SRT settings (RTT={rtt:.1f}ms, Loss={loss:.1f}%): {results}"); return results

    def get_fallback_results(self, error_msg="Test failed or no servers available"):
        """Returns a default dictionary when tests fail."""
        # --- This method remains unchanged ---
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S"); logger.warning(f"Returning fallback results at {now}. Reason: {error_msg}")
        return {'server': "N/A", 'server_location': "N/A", 'rtt_ms': None, 'loss_percent': None, 'jitter_ms': None, 'bandwidth_mbps': None, 'latency_recommendation': 120, 'overhead_recommendation': 25, 'rtt_multiplier': 4, 'test_time': now, 'error': error_msg }

    # --- run_network_test: Updated to call TCP test on high RTT ---
    def run_network_test(self, mode, region, manual_host, manual_port, duration, bitrate, location_info):
        """
        Main method to orchestrate network tests based on the selected mode.
        Falls back to TCP iperf3 test if RTT is too high for UDP.
        Accepts location_info dict obtained from the route.
        Returns a dictionary formatted for the frontend JS.
        """
        logger.info(f"Running network test: mode={mode}, region={region}, manual_host={manual_host}, duration={duration}, bitrate={bitrate}")
        if not self.servers: logger.warning("Server list empty, reloading."); self.load_servers();
        if not self.servers: return self.get_fallback_results("Server list unavailable.")

        target_servers_to_test = []; test_target_label = "N/A"; aggregation_needed = False; best_rtt_server_info = None

        # --- Determine Target Server(s) (Logic remains the same) ---
        if mode == 'manual':
            if not manual_host: return self.get_fallback_results("Manual mode: No host provided.")
            m_port = int(manual_port) if manual_port else DEFAULT_IPERF_PORT
            target_servers_to_test = [{'host': manual_host, 'port': m_port, 'site': 'Manual Input'}]
            test_target_label = f"Manual: {manual_host}:{m_port}"
        elif mode == 'regional':
            if not region: return self.get_fallback_results("Regional mode: No region provided.")
            regional_servers = [s for s in self.servers if s.get('continent') == region]
            if not regional_servers: return self.get_fallback_results(f"No servers for region: {region}")
            num_to_select = min(3, len(regional_servers)); target_servers_to_test = random.sample(regional_servers, num_to_select)
            target_labels = [f"{s['host']}:{s['port']}" for s in target_servers_to_test]
            test_target_label = f"{num_to_select} Random in {region}: {', '.join(target_labels)}"; aggregation_needed = True
        else: # 'closest'
            mode = 'closest'
            if not location_info or location_info.get('error'): return self.get_fallback_results(f"Location unavailable: {location_info.get('error', 'GeoIP Error') if location_info else 'GeoIP unavailable'}")
            continent_name = location_info.get('continent');
            if not continent_name: return self.get_fallback_results(f"Could not get continent: {location_info}")
            regional_servers = [s for s in self.servers if s.get('continent') == continent_name]
            if not regional_servers: return self.get_fallback_results(f"No servers for region: {continent_name}")
            num_candidates = min(7, len(regional_servers)); candidates_to_ping = random.sample(regional_servers, num_candidates)
            ping_results = []; logger.info(f"Pinging up to {num_candidates} candidates in {continent_name}...")
            for server in candidates_to_ping:
                rtt = self.run_ping(server['host'])
                if rtt is not None: server['rtt'] = rtt; ping_results.append(server)
            if not ping_results: return self.get_fallback_results(f"Ping failed for all candidates in {continent_name}.")
            ping_results.sort(key=lambda x: x['rtt']); best_rtt_server_info = ping_results[0]
            target_servers_to_test = [best_rtt_server_info];
            test_target_label = f"Closest: {best_rtt_server_info['host']}:{best_rtt_server_info['port']} ({best_rtt_server_info.get('site', 'N/A')}, {best_rtt_server_info['rtt']:.1f}ms)"

        # --- Run Tests (Calling UDP or TCP based on RTT) ---
        all_results_raw = []
        if not target_servers_to_test: return self.get_fallback_results("No target servers selected.")

        for server in target_servers_to_test:
            host = server['host']; port = server['port']
            logger.info(f"\n--- Testing server: {host}:{port} ---")
            rtt = server.get('rtt');
            if rtt is None: rtt = self.run_ping(host)

            iperf_result = None
            if rtt is None:
                 logger.warning(f"Skipping iperf3 test for {host}:{port} because ping failed.")
                 iperf_result = {'type': 'N/A', 'error': 'Ping failed'}
            # --- >>> TCP Fallback Logic <<< ---
            elif rtt > RTT_THRESHOLD_FOR_TCP_FALLBACK:
                 logger.warning(f"High RTT ({rtt:.1f}ms > {RTT_THRESHOLD_FOR_TCP_FALLBACK}ms), falling back to TCP iperf3 test for {host}:{port}.")
                 # Use the default TCP duration from constants
                 iperf_result = self.run_iperf3_tcp(host, port, duration=IPERF_TCP_DURATION)
            # --- >>> End TCP Fallback <<< ---
            else:
                 # RTT is acceptable, run the standard UDP test
                 # Pass the duration/bitrate selected in the form
                 iperf_result = self.run_iperf3_udp(host, port, bitrate=bitrate, duration=duration)

            all_results_raw.append({'host': host, 'port': port, 'site': server.get('site', 'N/A'), 'rtt': rtt, 'iperf': iperf_result})
            if mode == 'closest' or mode == 'manual': break


        # --- Aggregate Results and Calculate SRT Settings ---
        valid_rtts = [r['rtt'] for r in all_results_raw if r.get('rtt') is not None]
        # Separate successful UDP and TCP results
        valid_udp_iperf = [r['iperf'] for r in all_results_raw if isinstance(r.get('iperf'), dict) and not r['iperf'].get('error') and r['iperf'].get('type') == 'UDP']
        valid_tcp_iperf = [r['iperf'] for r in all_results_raw if isinstance(r.get('iperf'), dict) and not r['iperf'].get('error') and r['iperf'].get('type') == 'TCP']
        # Count failures (excluding Ping failed, as RTT check handles that)
        iperf_failures = [r['iperf'] for r in all_results_raw if isinstance(r.get('iperf'), dict) and r['iperf'].get('error') and r['iperf'].get('error') != 'Ping failed']

        if not valid_rtts: return self.get_fallback_results("Ping tests failed for all selected servers.")

        avg_rtt = sum(valid_rtts) / len(valid_rtts)

        # Initialize metrics
        aggregate_loss = None
        aggregate_jitter = None
        aggregate_bandwidth_udp = None
        aggregate_bandwidth_tcp = None
        srt_settings = None
        final_error_msg = None

        if valid_udp_iperf: # Prioritize UDP results if available
            losses = [float(p['loss_percent']) for p in valid_udp_iperf if p.get('loss_percent') is not None]
            jitters = [float(p['jitter_ms']) for p in valid_udp_iperf if p.get('jitter_ms') is not None]
            bandwidths = [float(p['bandwidth_mbps']) for p in valid_udp_iperf if p.get('bandwidth_mbps') is not None]

            aggregate_loss = max(losses) if losses else 0.0 # Default to 0 if UDP ran but reported no loss
            aggregate_jitter = sum(jitters) / len(jitters) if jitters else None
            aggregate_bandwidth_udp = sum(bandwidths) / len(bandwidths) if bandwidths else None

            # Calculate SRT settings using measured UDP loss
            srt_settings = self.calculate_srt_settings(avg_rtt, aggregate_loss)
            logger.info("Using UDP results for SRT calculation.")

        elif valid_tcp_iperf: # Fallback to TCP results if no UDP results
            bandwidths = [float(p['bandwidth_mbps']) for p in valid_tcp_iperf if p.get('bandwidth_mbps') is not None]
            aggregate_bandwidth_tcp = sum(bandwidths) / len(bandwidths) if bandwidths else None

            # Calculate estimated SRT settings using assumed loss
            aggregate_loss = ASSUMED_LOSS_FOR_TCP_FALLBACK # Use the assumed loss
            srt_settings = self.calculate_srt_settings(avg_rtt, aggregate_loss)
            logger.warning(f"No valid UDP results. Using TCP results (Avg BW: {aggregate_bandwidth_tcp} Mbps) and assumed {aggregate_loss}% loss for SRT calculation.")
            # Add a note to the error field even if technically successful
            final_error_msg = f"SRT settings estimated (Used TCP test, assumed {aggregate_loss}% loss)"


        else: # No valid UDP or TCP results, only ping worked (or ping also failed but caught earlier)
            first_error = iperf_failures[0].get('error', 'iperf3 tests failed') if iperf_failures else "iperf3 tests failed"
            error_msg = f"{first_error} (Avg RTT: {avg_rtt:.1f}ms)"
            logger.warning(error_msg + ", returning ping-based results.")
            fallback = self.get_fallback_results(error_msg)
            fallback['rtt_ms'] = avg_rtt; fallback['server'] = test_target_label
            fallback['server_location'] = best_rtt_server_info.get('site', 'N/A') if best_rtt_server_info else (target_servers_to_test[0].get('site','N/A') if len(target_servers_to_test)==1 else (region or "Multiple"))
            # Calculate estimated SRT settings using assumed loss
            srt_settings_fallback = self.calculate_srt_settings(avg_rtt, ASSUMED_LOSS_FOR_TCP_FALLBACK)
            if srt_settings_fallback: fallback.update({'latency_recommendation': srt_settings_fallback.get('latency_ms'), 'overhead_recommendation': srt_settings_fallback.get('overhead_percent'), 'rtt_multiplier': srt_settings_fallback.get('rtt_multiplier')})
            return fallback # Return the full fallback dictionary

        # Determine location display string
        server_location_display = "N/A";
        if mode == 'closest' and best_rtt_server_info: server_location_display = best_rtt_server_info.get('site', 'N/A')
        elif mode == 'manual': server_location_display = "Manual Input"
        elif mode == 'regional': sites = list(set(s.get('site', 'N/A') for s in target_servers_to_test)); server_location_display = region if len(sites) > 1 else sites[0]

        # --- Format final result for frontend ---
        final_result = {
            'server': test_target_label, 'server_location': server_location_display,
            'rtt_ms': avg_rtt,
            'loss_percent': aggregate_loss, # Will be the assumed loss if UDP failed
            'jitter_ms': aggregate_jitter, # Will be None if UDP failed
            'bandwidth_mbps': aggregate_bandwidth_udp if aggregate_bandwidth_udp is not None else aggregate_bandwidth_tcp, # Show UDP BW if available, else TCP BW
            'bandwidth_type': 'UDP' if aggregate_bandwidth_udp is not None else ('TCP' if aggregate_bandwidth_tcp is not None else None), # Indicate BW type
            'latency_recommendation': srt_settings.get('latency_ms') if srt_settings else None,
            'overhead_recommendation': srt_settings.get('overhead_percent') if srt_settings else None,
            'rtt_multiplier': srt_settings.get('rtt_multiplier') if srt_settings else None,
            'test_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'error': final_error_msg # Null if UDP worked, message if TCP fallback used
        }
        return final_result
