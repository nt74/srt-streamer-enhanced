# /opt/srt-streamer-enhanced/app/stream_manager.py
import gi
gi.require_version('Gst', '1.0')
gi.require_version('Gio', '2.0')
from gi.repository import Gst, GLib, GObject, Gio
import threading
import logging
import os
import subprocess
import time
import re
import json
from collections import defaultdict
from app.dvb_config import DVB_STANDARD_CONFIG

# Initialize GStreamer
Gst.init(None)

class StreamManager:
    def __init__(self, media_folder):
        self.media_folder = media_folder
        self.active_streams = {}
        self.lock = threading.RLock()
        self.mainloop = GLib.MainLoop()
        self.thread = threading.Thread(target=self.mainloop.run)
        self.thread.daemon = True
        self.thread.start()
        self.logger = logging.getLogger(__name__)
        self.logger.addHandler(logging.StreamHandler())
        self.logger.setLevel(logging.INFO)
        self.logger.info(f"StreamManager initialized with media folder: {media_folder}")

    def _validate_listener_port(self, port):
        try:
            port_int = int(port)
            if port_int < 10001 or port_int > 10010:
                raise ValueError(f"Listener port {port_int} outside range")
            return port_int
        except (ValueError, TypeError) as e:
            self.logger.error(f"Invalid listener port: {port}")
            raise ValueError(f"Invalid listener port: {port}.")

    def _validate_target_port(self, port):
        try:
            port_int = int(port)
            if port_int < 1 or port_int > 65535:
                raise ValueError(f"Target port {port_int} outside range")
            return port_int
        except (ValueError, TypeError) as e:
            self.logger.error(f"Invalid target port: {port}")
            raise ValueError(f"Invalid target port: {port}.")

    def _sanitize_for_json(self, obj):
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        elif isinstance(obj, (list, tuple)):
            return [self._sanitize_for_json(item) for item in obj]
        elif isinstance(obj, dict):
            return {str(k): self._sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, (Gio.SocketAddress, Gio.InetAddress)):
            return self._extract_ip_from_socket_address(obj)
        elif isinstance(obj, GLib.Error):
            return f"GLib.Error: {obj.message} (domain:{obj.domain}, code:{obj.code})"
        elif isinstance(obj, GObject.GObject):
            try:
                if hasattr(obj, 'to_string') and callable(obj.to_string):
                    return obj.to_string()
            except Exception:
                pass
            return str(obj)
        else:
            try:
                return json.dumps(obj)
            except TypeError:
                return str(obj)

    def _extract_ip_from_socket_address(self, addr):
        if addr is None:
            return "unknown-address"
        try:
            if isinstance(addr, Gio.InetAddress):
                return addr.to_string()
            elif isinstance(addr, Gio.InetSocketAddress):
                return addr.get_address().to_string()
            addr_str = str(addr)
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', addr_str)
            if ip_match:
                return ip_match.group(1)
            return addr_str
        except Exception as e:
            self.logger.error(f"Error extracting IP: {str(e)}")
            return str(addr)

    def _on_bus_message(self, bus, message, key):
        t = message.type
        if t == Gst.MessageType.EOS:
            self.logger.info(f"EOS received for stream {key}")
            self.stop_stream(key)
        elif t == Gst.MessageType.ERROR:
            err, debug = message.parse_error()
            self.logger.error(f"Error on stream {key}: {err.message}, Debug: {debug}")
            self.stop_stream(key)
        elif t == Gst.MessageType.WARNING:
            warn, debug = message.parse_warning()
            self.logger.warning(f"Warning on stream {key}: {warn.message}")

    def _on_caller_added(self, element, socket_id, addr, key):
        ip = self._extract_ip_from_socket_address(addr)
        self.logger.info(f"SRT caller connected for stream {key}: id={socket_id}, addr={ip}")
        with self.lock:
            if key in self.active_streams:
                stream_info = self.active_streams[key]
                stream_info['connection_status'] = 'Connected'
                stream_info['connected_client'] = ip
                stream_info['socket_id'] = socket_id
                stream_info.setdefault('connection_history', []).append({
                    'event': 'connected',
                    'time': time.time(),
                    'ip': ip,
                    'socket_id': socket_id
                })

    def _on_caller_removed(self, element, socket_id, addr, key):
        ip = self._extract_ip_from_socket_address(addr)
        self.logger.info(f"SRT caller disconnected for stream {key}: id={socket_id}, addr={ip}")
        with self.lock:
            if key in self.active_streams:
                stream_info = self.active_streams[key]
                stream_info['connection_status'] = 'Waiting for connection' if stream_info.get('mode') == 'listener' else 'Disconnected'
                stream_info['connected_client'] = None
                stream_info.setdefault('connection_history', []).append({
                    'event': 'disconnected',
                    'time': time.time(),
                    'ip': ip,
                    'socket_id': socket_id
                })

    def _on_caller_rejected(self, element, addr, reason, key):
        ip = self._extract_ip_from_socket_address(addr)
        self.logger.warning(f"SRT caller rejected for stream {key}: addr={ip}, reason={reason}")
        with self.lock:
            if key in self.active_streams:
                stream_info = self.active_streams[key]
                stream_info['connection_status'] = 'Rejected'
                stream_info.setdefault('connection_history', []).append({
                    'event': 'rejected',
                    'time': time.time(),
                    'ip': ip,
                    'reason': reason
                })

    def start_stream(self, file_path, config, use_target_port_as_key=False):
        key = None
        pipeline = None
        existing_pipeline = None
        try:
            mode = config.get('mode', 'listener')
            if mode == 'caller':
                if not use_target_port_as_key:
                    raise ValueError("Caller mode needs target port key.")
                key = self._validate_target_port(config.get('target_port'))
            else:
                key = self._validate_listener_port(config.get('port'))

            with self.lock:
                if key in self.active_streams:
                    self.logger.warning(f"Stream key {key} already in use. Stopping existing.")
                    existing_pipeline = self.active_streams[key].get('pipeline')
                    del self.active_streams[key]

            if existing_pipeline:
                GLib.idle_add(existing_pipeline.set_state, Gst.State.NULL, priority=GLib.PRIORITY_DEFAULT)
                self.logger.info(f"Scheduled stop for old pipeline {key}.")

            if not file_path or not isinstance(file_path, str):
                raise ValueError("Invalid file path")
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            if not file_path.lower().endswith('.ts'):
                raise ValueError("Invalid file type: Only .ts")

            overhead_bandwidth = int(config.get('overhead_bandwidth', 25))
            smoothing_latency_us = 20000
            latency_ms = int(config.get('latency', DVB_STANDARD_CONFIG['srt_latency']))
            encryption = config.get('encryption', 'none')
            sink_name = f"srtsink_{key}"
            tsparse_name = f"tsparse_{key}"

            srt_params = [
                f"mode={mode}",
                "transtype=live",
                f"latency={latency_ms}",
                f"peerlatency={latency_ms}",
                f"rcvbuf={DVB_STANDARD_CONFIG['rcvbuf']}",
                f"sndbuf={DVB_STANDARD_CONFIG['sndbuf']}",
                f"fc={DVB_STANDARD_CONFIG['fc']}",
                f"tlpktdrop={str(DVB_STANDARD_CONFIG['tlpktdrop']).lower()}",
                f"overheadbandwidth={overhead_bandwidth}",
                "nakreport=1",
                f"streamid=dvb_stream_{key}"
            ]

            if encryption != 'none':
                passphrase = config.get('passphrase', '')
                if not passphrase or len(passphrase) < 10:
                    raise ValueError("Passphrase required")
                srt_params.append(f"passphrase={passphrase}")
                pbkeylen = 16 if encryption == 'aes-128' else 32
                srt_params.append(f"pbkeylen={pbkeylen}")

            if mode == 'caller':
                target_address = config.get('target_address')
                target_port = key
                if not target_address:
                    raise ValueError("Target address required")
                srt_uri = f"srt://{target_address}:{target_port}?{'&'.join(srt_params)}"
            else:
                listen_ip = "0.0.0.0"
                listener_port = key
                srt_uri = f"srt://{listen_ip}:{listener_port}?{'&'.join(srt_params)}"

            pipeline_str = f'filesrc location="{file_path}" ! tsparse name="{tsparse_name}" set-timestamps=true alignment=7 smoothing-latency={smoothing_latency_us} parse-private-sections=true ! srtsink name="{sink_name}" uri="{srt_uri}" wait-for-connection=true'
            pipeline_str = " ".join(pipeline_str.split())
            self.logger.info(f"Constructed pipeline key {key}: {pipeline_str}")

            pipeline = Gst.parse_launch(pipeline_str)
            if not pipeline:
                self.logger.error(f"Pipeline creation failed for key {key}.")
                return False, f"Pipeline creation failed for key {key}"

            bus = pipeline.get_bus()
            bus.add_signal_watch()
            bus.connect("message", self._on_bus_message, key)

            srtsink = pipeline.get_by_name(sink_name)
            if not srtsink:
                self.logger.error(f"Cannot find '{sink_name}' key {key}.")
                GLib.idle_add(pipeline.set_state, Gst.State.NULL)
                return False, f"Cannot find SRT sink element for stream {key}"

            try:
                srtsink.connect('caller-added', self._on_caller_added, key)
                srtsink.connect('caller-removed', self._on_caller_removed, key)
                srtsink.connect('caller-rejected', self._on_caller_rejected, key)
            except Exception as e:
                self.logger.warning(f"Signal connect error key {key}: {str(e)}")

            stream_info_dict = {
                'pipeline': pipeline,
                'config': config,
                'file_path': file_path,
                'srt_uri': srt_uri,
                'mode': mode,
                'start_time': time.time(),
                'connection_status': 'Connecting...' if mode == 'caller' else 'Waiting for connection',
                'connected_client': None,
                'socket_id': None,
                'connection_history': []
            }
            if mode == 'caller':
                stream_info_dict['target'] = f"{target_address}:{target_port}"

            with self.lock:
                self.active_streams[key] = stream_info_dict

            def set_playing_safe(p, k):
                ret = p.set_state(Gst.State.PLAYING)
                if ret == Gst.StateChangeReturn.FAILURE:
                    self.logger.error(f"Failed pipeline {k} PLAYING.")
                elif ret == Gst.StateChangeReturn.ASYNC:
                    self.logger.info(f"Pipeline {k} PLAYING ASYNC.")
                else:
                    self.logger.info(f"Pipeline {k} PLAYING sync/no-preroll.")

            GLib.idle_add(set_playing_safe, pipeline, key)
            return True, f"Stream {mode} ({key}) starting: {srt_uri}"

        except (ValueError, FileNotFoundError) as e:
            self.logger.error(f"Config/file error key {key or 'N/A'}: {str(e)}")
            return False, f"Configuration or file error: {str(e)}"
        except Exception as e:
            self.logger.error(f"Unexpected start error {key or 'N/A'}: {str(e)}", exc_info=True)
            return False, f"Unexpected error: {str(e)}"
        finally:
            if 'pipeline' in locals() and pipeline and key not in self.active_streams:
                GLib.idle_add(pipeline.set_state, Gst.State.NULL)

    def stop_stream(self, stream_key):
        pipeline_to_stop = None
        key = -1
        try:
            try:
                key = int(stream_key)
            except (ValueError, TypeError):
                raise ValueError(f"Invalid stream identifier: {stream_key}")
            
            with self.lock:
                if key not in self.active_streams:
                    self.logger.warning(f"Stop failed: Stream {key} not found")
                    return False, "Stream not found"
                
                self.logger.info(f"Stopping stream key: {key}")
                stream_info = self.active_streams.pop(key)
                pipeline_to_stop = stream_info.get('pipeline')

            if pipeline_to_stop:
                self.logger.info(f"Scheduling pipeline {key} NULL.")
                GLib.idle_add(pipeline_to_stop.set_state, Gst.State.NULL, priority=GLib.PRIORITY_DEFAULT)
                return True, f"Stream ({key}) stopped."
            else:
                self.logger.warning(f"No pipeline found for key {key}")
                return False, "Stream active but no pipeline."
        except ValueError as e:
            self.logger.error(f"Stop validation error: {str(e)}")
            return False, str(e)
        except Exception as e:
            self.logger.error(f"Unexpected stop error {stream_key}: {str(e)}", exc_info=True)
            if pipeline_to_stop:
                GLib.idle_add(pipeline_to_stop.set_state, Gst.State.NULL)
            return False, f"Unexpected error stopping stream: {str(e)}"

    def get_active_streams(self):
        with self.lock:
            streams_copy = {k: v.copy() for k, v in self.active_streams.items()}
        
        sanitized_result = {}
        for key, stream in streams_copy.items():
            try:
                config = stream.get('config', {})
                data = {
                    'key': key,
                    'file_path': stream.get('file_path', 'N/A'),
                    'mode': stream.get('mode', 'listener'),
                    'latency': config.get('latency', DVB_STANDARD_CONFIG['srt_latency']),
                    'overhead_bandwidth': config.get('overhead_bandwidth', 25),
                    'encryption': config.get('encryption', 'none'),
                    'passphrase_set': config.get('encryption', 'none') != 'none' and config.get('passphrase', ''),
                    'srt_uri': stream.get('srt_uri', ''),
                    'connection_status': stream.get('connection_status', 'Unknown'),
                    'connected_client': self._extract_ip_from_socket_address(stream.get('connected_client')),
                    'target': stream.get('target', None),
                    'start_time': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(stream.get('start_time', 0)))
                }
                sanitized_result[key] = data
            except Exception as e:
                self.logger.error(f"Error processing stream {key}: {e}")
                continue
        return sanitized_result

    def _extract_stats_from_gstruct(self, stats_struct):
        """Parse SRT statistics from GStreamer structure with decimal rounding."""
        result = {}
        if not stats_struct:
            return result

        try:
            stats_str = stats_struct.to_string()
            if not stats_str:
                return result

            # Clean up the string by removing escapes and extra quotes
            cleaned_str = stats_str.replace('\\', '').replace('\"', '')

            # Extract the main stats section (after callers=)
            main_stats_match = re.search(r'callers=\(GValueArray\)<\s*(.*?)\s*>', cleaned_str)
            if main_stats_match:
                main_stats = main_stats_match.group(1)
            else:
                main_stats = cleaned_str

            # Handle bytes-sent-total separately as it's outside the main stats
            bytes_total_match = re.search(r'bytes-sent-total=\([^)]+\)([0-9]+)', cleaned_str)
            if bytes_total_match:
                result['bytes_sent_total'] = int(bytes_total_match.group(1))

            # Improved regex pattern to handle all value types
            pattern = re.compile(
                r'([a-zA-Z0-9\-]+)='
                r'\(([^)]+)\)'
                r'([0-9]+(?:\.[0-9]+(?:e[+-]?[0-9]+)?)?|NULL|TRUE|FALSE)'
                r'(?:[,;]|$)'
            )
            
            matches = pattern.finditer(main_stats)
            for match in matches:
                key = match.group(1).replace('-', '_')
                value_type = match.group(2)
                value_str = match.group(3)
                
                if value_str == "NULL":
                    result[key] = None
                    continue
                    
                try:
                    if value_type.startswith(('gint', 'int', 'guint', 'long')):
                        result[key] = int(value_str)
                    elif value_type.startswith(('double', 'float')):
                        # Convert to float first, then round to 2 decimal places
                        result[key] = round(float(value_str), 2)
                    elif value_str in ('TRUE', 'FALSE'):
                        result[key] = value_str == 'TRUE'
                    else:
                        result[key] = value_str
                except ValueError:
                    result[key] = value_str

            # Create friendly aliases that match HTML template expectations
            metric_aliases = {
                'packets_sent': 'packets_sent_total',
                'packets_sent_lost': 'packets_lost_total',
                'send_rate_mbps': 'bitrate_mbps',
                'rtt_ms': 'rtt_ms',
                'bandwidth_mbps': 'estimated_bandwidth_mbps',
                'negotiated_latency_ms': 'negotiated_latency_ms',
                'packets_received': 'packets_received_total',
                'bytes_sent': 'bytes_sent',
                'bytes_received': 'bytes_received',
                'bytes_received_lost': 'bytes_received_lost',
                'bytes_retransmitted': 'bytes_retransmitted',
                'bytes_sent_dropped': 'bytes_sent_dropped',
                'packet_ack_received': 'packet_ack_received',
                'packet_nack_received': 'packet_nack_received',
                'packet_ack_sent': 'packet_ack_sent',
                'packet_nack_sent': 'packet_nack_sent',
                'packets_received_lost': 'packets_received_lost',
                'packets_received_retransmitted': 'packets_received_retransmitted',
                'packets_received_dropped': 'packets_received_dropped',
                'packets_retransmitted': 'packets_retransmitted',
                'packets_sent_dropped': 'packets_sent_dropped',
                'receive_rate_mbps': 'receive_rate_mbps',
                'send_duration_us': 'send_duration_us',
                'snd_buf_ms': 'send_buffer_level_ms',
                'rcv_buf_ms': 'recv_buffer_level_ms',
                'flow_wnd': 'flow_window'
            }

            # Apply aliases and set defaults for HTML-expected metrics
            for src, dest in metric_aliases.items():
                if src in result:
                    result[dest] = result[src]
                elif dest not in result:
                    if dest.endswith('_mbps'):
                        result[dest] = 0.0
                    elif dest.endswith(('_ms', '_us')):
                        result[dest] = 0
                    elif dest.startswith(('packets_', 'bytes_', 'packet_')):
                        result[dest] = 0
                    else:
                        result[dest] = None

            # Calculate derived metrics expected by HTML
            sent_total = result.get('packets_sent_total', 1)
            lost_total = result.get('packets_lost_total', 0)
            result['packet_loss_percent'] = round((lost_total / sent_total) * 100, 2)

            return result

        except Exception as e:
            self.logger.error(f"Error parsing stats: {str(e)}", exc_info=True)
            return {'error': str(e), 'raw_string': stats_str}

    def get_stream_statistics(self, stream_key):
        """Get comprehensive statistics for a stream in structured format."""
        try:
            key = int(stream_key)
            with self.lock:
                if key not in self.active_streams:
                    self.logger.warning(f"No stream {key} in stats fetch")
                    return None
                stream_info = self.active_streams[key].copy()

            # Initialize stats structure
            stats = {
                'connection_status': stream_info.get('connection_status', 'Unknown'),
                'connected_client': self._extract_ip_from_socket_address(
                    stream_info.get('connected_client')),
                'uptime': self._format_uptime(time.time() - stream_info.get('start_time', time.time())),
                'last_updated': time.time()
            }

            # Get stats from pipeline if available
            pipeline = stream_info.get('pipeline')
            if pipeline:
                sink_name = f"srtsink_{key}"
                srtsink = pipeline.get_by_name(sink_name)
                if srtsink:
                    try:
                        stats_struct = srtsink.get_property('stats')
                        if stats_struct:
                            parsed_stats = self._extract_stats_from_gstruct(stats_struct)
                            stats.update(parsed_stats)
                    except Exception as e:
                        self.logger.error(f"Error processing stats for key {key}: {str(e)}", exc_info=True)

            return stats

        except ValueError as e:
            self.logger.error(f"Get stats validation error key {stream_key}: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected get stats error key {stream_key}: {str(e)}", exc_info=True)
            return None

    def _format_uptime(self, seconds):
        try:
            seconds_int = int(seconds)
            if seconds_int < 0:
                return "0s"
            
            hours, remainder = divmod(seconds_int, 3600)
            minutes, sec = divmod(remainder, 60)
            
            parts = []
            if hours > 0:
                parts.append(f"{hours}h")
            if minutes > 0 or hours > 0:
                parts.append(f"{minutes}m")
            parts.append(f"{sec}s")
            return " ".join(parts)
        except Exception as e:
            self.logger.error(f"Error formatting uptime: {str(e)}")
            return "0s"

    def get_file_info(self, file_path):
        try:
            cmd = ['ffprobe', '-v', 'error', '-show_format', '-show_streams', '-of', 'json', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=20)
            return json.loads(result.stdout)
        except FileNotFoundError:
            self.logger.warning("ffprobe not found, trying mediainfo...")
            try:
                cmd = ['mediainfo', '--Output=JSON', file_path]
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
                return json.loads(result.stdout)
            except Exception as e:
                return {"error": f"Failed to get file info: {str(e)}"}
        except Exception as e:
            return {"error": f"Error getting file info: {str(e)}"}

    def get_debug_info(self, stream_key):
        try:
            key = int(stream_key)
            with self.lock:
                if key not in self.active_streams:
                    return {"error": f"Stream {key} not found"}
                stream_info = self.active_streams[key].copy()

            debug_info = {
                "stream_key": key,
                "mode": stream_info.get('mode', '?'),
                "file_path": stream_info.get('file_path'),
                "target": stream_info.get('target'),
                "uri": stream_info.get('srt_uri'),
                "status": stream_info.get('connection_status'),
                "client_ip": self._extract_ip_from_socket_address(stream_info.get('connected_client')),
                "uptime": self._format_uptime(time.time() - stream_info.get('start_time', time.time())),
                "config": stream_info.get('config', {}),
                "connection_history": stream_info.get('connection_history', [])
            }

            pipeline = stream_info.get('pipeline')
            if pipeline:
                sink_name = f"srtsink_{key}"
                srtsink = pipeline.get_by_name(sink_name)
                if srtsink:
                    try:
                        stats_struct = srtsink.get_property('stats')
                        if stats_struct:
                            debug_info["raw_stats"] = stats_struct.to_string()
                            debug_info["parsed_stats"] = self._extract_stats_from_gstruct(stats_struct)
                    except Exception as e:
                        debug_info["stats_error"] = str(e)

            return debug_info
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            self.logger.error(f"Debug info error: {str(e)}", exc_info=True)
            return {"error": f"Unexpected error: {str(e)}"}
