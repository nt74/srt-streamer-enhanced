# /opt/srt-streamer-enhanced/app/stream_manager.py
# V12: Modified stop_stream to use synchronous set_state(NULL) call.

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
from app.dvb_config import DVB_STANDARD_CONFIG # Correct import

# Initialize GStreamer
Gst.init(None)

class StreamManager:
    # --- __init__ (Correct signature) ---
    def __init__(self, media_folder):
        self.media_folder = media_folder
        self.active_streams = {}
        self.lock = threading.RLock()
        self.mainloop = GLib.MainLoop()
        self.thread = threading.Thread(target=self.mainloop.run)
        self.thread.daemon = True
        self.thread.start()
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers: self.logger.addHandler(logging.StreamHandler()) # Ensure logger has handlers
        self.logger.setLevel(logging.INFO)
        self.logger.info(f"StreamManager initialized with media folder: {media_folder}")
        try: self.logger.info(f"GStreamer version: {Gst.version_string()}")
        except Exception as e: self.logger.error(f"Could not get GStreamer version string: {e}")

    # --- Validation Methods (Keep as is) ---
    def _validate_listener_port(self, port):
        try: port_int = int(port);
        except (ValueError, TypeError) as e: self.logger.error(f"Invalid listener port format or value: {port} - {e}"); raise ValueError(f"Invalid listener port: {port}. Must be between 10001 and 10010.")
        if not (10001 <= port_int <= 10010): raise ValueError(f"Listener port {port_int} is outside the allowed range (10001-10010)");
        return port_int
    def _validate_target_port(self, port):
        try: port_int = int(port);
        except (ValueError, TypeError) as e: self.logger.error(f"Invalid target port format or value: {port} - {e}"); raise ValueError(f"Invalid target port: {port}. Must be between 1 and 65535.")
        if not (1 <= port_int <= 65535): raise ValueError(f"Target port {port_int} is outside the valid range (1-65535)");
        return port_int

    # --- Sanitization/Extraction Methods (Keep as is) ---
    def _sanitize_for_json(self, obj):
        # (Keep existing V10 implementation)
        if isinstance(obj, (str, int, float, bool, type(None))): return obj
        elif isinstance(obj, (list, tuple)): return [self._sanitize_for_json(item) for item in obj]
        elif isinstance(obj, dict): return {str(k): self._sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, (Gio.SocketAddress, Gio.InetAddress, Gio.InetSocketAddress)): return self._extract_ip_from_socket_address(obj)
        elif isinstance(obj, GLib.Error): return f"GLib.Error: {obj.message} (domain:{obj.domain}, code:{obj.code})"
        elif isinstance(obj, GObject.GObject):
            try:
                if hasattr(obj, 'to_string') and callable(obj.to_string): return obj.to_string()
                elif hasattr(obj, 'get_name') and callable(obj.get_name): return f"{type(obj).__name__}(name='{obj.get_name()}')"
            except Exception: pass
            return str(obj)
        else:
            try: json.dumps(obj); return obj
            except TypeError: return str(obj)

    def _extract_ip_from_socket_address(self, addr):
        # (Keep existing V10 implementation)
        if addr is None: return "unknown-address"
        try:
            if isinstance(addr, Gio.InetSocketAddress): inet_addr = addr.get_address(); return inet_addr.to_string() if inet_addr else "unknown-inet-address"
            elif isinstance(addr, Gio.InetAddress): return addr.to_string()
            elif isinstance(addr, Gio.SocketAddress):
                 family = addr.get_family()
                 if family == Gio.SocketFamily.IPV4 or family == Gio.SocketFamily.IPV6:
                     try:
                         inet_sock_addr = addr.cast(Gio.InetSocketAddress)
                         if inet_sock_addr: inet_addr = inet_sock_addr.get_address(); return inet_addr.to_string() if inet_addr else "unknown-inet-address"
                     except TypeError: pass
                 addr_str = addr.to_string(); ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', addr_str); return ip_match.group(1) if ip_match else addr_str
            else: return str(addr)
        except Exception as e: self.logger.error(f"Error extracting IP from address object ({type(addr)}): {str(e)}"); return str(addr)

    # --- GStreamer Bus/Signal Handlers (With V10 Logging) ---
    def _on_bus_message(self, bus, message, key):
        t = message.type
        stream_info = self.active_streams.get(key)
        pipeline_description = f"stream {key}"
        if stream_info:
            pipeline_description = f"stream {key} ({stream_info.get('mode', '?')} {'to '+stream_info.get('target', '') if stream_info.get('mode')=='caller' else ''})"
            # Detailed state change logging
            if t == Gst.MessageType.STATE_CHANGED:
                if message.src == stream_info.get('pipeline'):
                    old_state, new_state, pending_state = message.parse_state_changed()
                    self.logger.info(
                        f"BUS_MSG: {pipeline_description} state changed from "
                        f"{Gst.Element.state_get_name(old_state)} to "
                        f"{Gst.Element.state_get_name(new_state)} "
                        f"(pending: {Gst.Element.state_get_name(pending_state)})"
                    )
                    if old_state == Gst.State.READY and new_state == Gst.State.PAUSED and pending_state == Gst.State.PLAYING:
                        self.logger.warning(f"BUS_MSG: {pipeline_description} reached PAUSED while trying to go to PLAYING.")
                    if old_state == Gst.State.PAUSED and new_state == Gst.State.READY and pending_state == Gst.State.NULL:
                         self.logger.info(f"BUS_MSG: {pipeline_description} reached READY while trying to go to NULL.")
                    # *** ADDED: Log if successfully reached NULL ***
                    if new_state == Gst.State.NULL:
                        self.logger.info(f"BUS_MSG: {pipeline_description} successfully transitioned to NULL state.")


        if t == Gst.MessageType.EOS:
            self.logger.info(f"BUS_MSG: EOS received for {pipeline_description}. Stopping.")
            self.stop_stream(key)
        elif t == Gst.MessageType.ERROR:
            err, debug = message.parse_error()
            src_name = message.src.get_name() if hasattr(message.src, 'get_name') else 'unknown source'
            self.logger.error(f"BUS_MSG: GStreamer error on {pipeline_description} from element '{src_name}': {err.message}. Debug: {debug}")
            with self.lock:
                if key in self.active_streams: self.active_streams[key]['connection_status'] = 'Error'
            self.stop_stream(key)
        elif t == Gst.MessageType.WARNING:
            warn, debug = message.parse_warning()
            src_name = message.src.get_name() if hasattr(message.src, 'get_name') else 'unknown source'
            self.logger.warning(f"BUS_MSG: GStreamer warning on {pipeline_description} from element '{src_name}': {warn.message}. Debug: {debug}")
            with self.lock:
                if key in self.active_streams:
                    current_status = self.active_streams[key].get('connection_status', 'Unknown'); new_status = None
                    msg_lower = warn.message.lower()
                    if "failed to authenticate" in msg_lower: new_status = "Auth Error"
                    elif "connection timed out" in msg_lower: new_status = "Timeout / Reconnecting"
                    elif "connection was broken" in msg_lower: new_status = "Broken / Reconnecting"
                    elif "could not bind" in msg_lower: new_status = "Bind Error"; self.logger.error(f"BUS_MSG: Detected potential port bind error via warning message for stream {key}.")
                    if new_status and current_status != new_status: self.active_streams[key]['connection_status'] = new_status; self.logger.info(f"Updated status for stream {key} to '{new_status}' based on warning.")

    # --- SRT Signal Handlers (Keep as is from V10) ---
    def _on_caller_added(self, element, socket_id, addr, key):
        # (Keep existing implementation)
        ip = self._extract_ip_from_socket_address(addr); self.logger.info(f"SRT signal 'caller-added' for stream {key}: socket_id={socket_id}, client_ip={ip}")
        with self.lock:
            if key in self.active_streams: stream_info = self.active_streams[key]; stream_info['connection_status'] = 'Connected'; stream_info['connected_client'] = addr ; stream_info['socket_id'] = socket_id; stream_info.setdefault('connection_history', []).append({ 'event': 'connected', 'time': time.time(), 'ip': ip, 'socket_id': socket_id }); self.logger.info(f"Updated stream {key} status to Connected, client: {ip}")
            else: self.logger.warning(f"SRT signal 'caller-added' received for non-existent stream key {key}")

    def _on_caller_removed(self, element, socket_id, addr, key):
        # (Keep existing implementation)
        ip = self._extract_ip_from_socket_address(addr)
        self.logger.info(f"SRT signal 'caller-removed' for stream {key}: socket_id={socket_id}, client_ip={ip}")
        with self.lock:
            if key in self.active_streams:
                stream_info = self.active_streams[key]
                if stream_info.get('socket_id') == socket_id:
                    stream_info['connection_status'] = 'Waiting for connection' if stream_info.get('mode') == 'listener' else 'Disconnected'
                    stream_info['connected_client'] = None
                    stream_info['socket_id'] = None
                    self.logger.info(f"Cleared tracked client for stream {key} as socket {socket_id} disconnected.")
                stream_info.setdefault('connection_history', []).append({ 'event': 'disconnected', 'time': time.time(), 'ip': ip, 'socket_id': socket_id})
            else:
                self.logger.warning(f"SRT signal 'caller-removed' received for non-existent or already stopped stream key {key}")

    def _on_caller_rejected(self, element, addr, reason, key):
        # (Keep existing implementation)
        ip = self._extract_ip_from_socket_address(addr); self.logger.warning(f"SRT signal 'caller-rejected' for stream {key}: client_ip={ip}, reason_code={reason}")
        with self.lock:
            if key in self.active_streams:
                self.active_streams[key]['connection_status'] = 'Rejected'
                self.active_streams[key].setdefault('connection_history', []).append({ 'event': 'rejected', 'time': time.time(), 'ip': ip, 'reason': reason })
            else: self.logger.warning(f"SRT signal 'caller-rejected' received for non-existent stream key {key}")

    # --- Core Stream Management ---
    def start_stream(self, file_path, config, use_target_port_as_key=False):
        # (Keep existing implementation from V10)
        key = None; pipeline = None; existing_pipeline = None
        try:
            mode = config.get('mode', 'listener')
            if mode == 'caller': key = self._validate_target_port(config.get('target_port'))
            else: key = self._validate_listener_port(config.get('port'))
            with self.lock:
                if key in self.active_streams: self.logger.warning(f"Stream key {key} ({mode}) already in use. Stopping existing stream first."); existing_pipeline = self.active_streams.pop(key).get('pipeline')
                else: self.logger.info(f"No existing stream found for key {key}. Proceeding to start new stream.")
            if existing_pipeline: self.logger.info(f"Scheduling destruction (set state to NULL) for old pipeline associated with key {key}."); GLib.idle_add(existing_pipeline.set_state, Gst.State.NULL, priority=GLib.PRIORITY_DEFAULT)
            if not file_path or not isinstance(file_path, str): raise ValueError("Invalid file path provided to start_stream.")
            if not os.path.isfile(file_path):
                 if not os.path.isabs(file_path): abs_path = os.path.join(self.media_folder, file_path); file_path = abs_path
                 if not os.path.isfile(file_path): raise FileNotFoundError(f"Media file not found: {file_path}")
            if not file_path.lower().endswith('.ts'): raise ValueError("Invalid file type: Only .ts files are supported.")
            overhead_bandwidth = int(config.get('overhead_bandwidth', 25)); smoothing_latency_us = 20000; latency_ms = int(config.get('latency', DVB_STANDARD_CONFIG.get('srt_latency', 300))); encryption = config.get('encryption', 'none'); passphrase = config.get('passphrase', ''); qos_enabled = config.get('qos', False); qos_string = str(qos_enabled).lower()
            sink_name = f"srtsink_{key}"; tsparse_name = f"tsparse_{key}"
            srt_params = [f"mode={mode}", "transtype=live", f"latency={latency_ms}", f"peerlatency={latency_ms}", f"rcvbuf={DVB_STANDARD_CONFIG.get('rcvbuf', 12058624)}", f"sndbuf={DVB_STANDARD_CONFIG.get('sndbuf', 12058624)}", f"fc={DVB_STANDARD_CONFIG.get('fc', 8000)}", f"tlpktdrop={str(DVB_STANDARD_CONFIG.get('tlpktdrop', True)).lower()}", f"overheadbandwidth={overhead_bandwidth}", "nakreport=true", f"streamid=dvb_stream_{key}", f"qos={qos_string}"]
            if encryption != 'none':
                if not passphrase or len(passphrase) < 10 or len(passphrase) > 79: raise ValueError("Passphrase required (10-79 characters) for encryption.")
                pbkeylen = 16 if encryption == 'aes-128' else 32
                srt_params.append(f"passphrase={passphrase}")
                srt_params.append(f"pbkeylen={pbkeylen}")
            if mode == 'caller': target_address = config.get('target_address'); target_port = key; srt_uri = f"srt://{target_address}:{target_port}?{'&'.join(srt_params)}"
            else: listen_ip = "0.0.0.0"; listener_port = key; srt_uri = f"srt://{listen_ip}:{listener_port}?{'&'.join(srt_params)}"
            pipeline_str = (f'filesrc location="{file_path}" ! '
                            f'tsparse name="{tsparse_name}" set-timestamps=true alignment=7 smoothing-latency={smoothing_latency_us} parse-private-sections=true ! '
                            f'srtsink name="{sink_name}" uri="{srt_uri}"')
            pipeline_str = " ".join(pipeline_str.split())
            self.logger.info(f"Constructed GStreamer pipeline for key {key}: {pipeline_str}")
            pipeline = Gst.parse_launch(pipeline_str);
            if not pipeline: self.logger.error(f"Failed to parse GStreamer pipeline string for key {key}."); return False, f"Pipeline creation failed for stream {key} (parsing error)."
            bus = pipeline.get_bus(); bus.add_signal_watch(); bus.connect("message", self._on_bus_message, key)
            srtsink = pipeline.get_by_name(sink_name);
            if not srtsink: self.logger.error(f"Cannot find '{sink_name}' element in the pipeline for key {key}."); GLib.idle_add(pipeline.set_state, Gst.State.NULL); return False, f"Cannot find SRT sink element '{sink_name}' for stream {key}."
            try: srtsink.connect('caller-added', self._on_caller_added, key); srtsink.connect('caller-removed', self._on_caller_removed, key); srtsink.connect('caller-rejected', self._on_caller_rejected, key); self.logger.info(f"Connected SRT signals for srtsink on stream {key}.")
            except Exception as e: self.logger.warning(f"Could not connect one or more SRT signals for srtsink on stream {key}: {str(e)}")
            stream_info_dict = {'pipeline': pipeline, 'bus': bus, 'config': config, 'file_path': file_path, 'srt_uri': srt_uri, 'mode': mode, 'start_time': time.time(), 'connection_status': 'Connecting...' if mode == 'caller' else 'Waiting for connection', 'connected_client': None, 'socket_id': None, 'connection_history': []}
            if mode == 'caller': stream_info_dict['target'] = f"{target_address}:{target_port}"
            with self.lock: self.active_streams[key] = stream_info_dict
            def set_playing_safe(p, k):
                self.logger.info(f"Attempting to set pipeline state to PLAYING for stream {k}...");
                ret = p.set_state(Gst.State.PLAYING)
                if ret == Gst.StateChangeReturn.FAILURE:
                    self.logger.error(f"Failed to set pipeline state to PLAYING for stream {k}.")
                    with self.lock:
                         if k in self.active_streams: self.active_streams[k]['connection_status'] = 'Start Error'
                    # Don't call stop_stream from here directly to avoid potential recursion if stop also fails
                    # Let bus error handler trigger stop if necessary
                elif ret == Gst.StateChangeReturn.ASYNC: self.logger.info(f"Pipeline state change to PLAYING is ASYNC for stream {k}.")
                elif ret == Gst.StateChangeReturn.SUCCESS: self.logger.info(f"Pipeline state change to PLAYING successful (sync) for stream {k}.")
                else: self.logger.info(f"Pipeline state change to PLAYING returned {ret.value_nick} for stream {k}.")
            GLib.idle_add(set_playing_safe, pipeline, key, priority=GLib.PRIORITY_DEFAULT)
            self.logger.info(f"Scheduled pipeline start (set state to PLAYING) for stream {key}.")
            return True, f"Stream {mode} ({key}) starting with URI: {srt_uri}"
        except (ValueError, FileNotFoundError) as e: self.logger.error(f"Stream start validation error for key {key or 'N/A'}: {str(e)}"); return False, f"Configuration or file error: {str(e)}"
        except Exception as e: self.logger.error(f"Unexpected error starting stream {key or 'N/A'}: {str(e)}", exc_info=True); return False, f"An unexpected error occurred: {str(e)}"
        finally:
             if 'pipeline' in locals() and pipeline and key not in self.active_streams: self.logger.warning(f"Cleaning up orphaned pipeline for key {key or 'N/A'} due to intermediate error."); GLib.idle_add(pipeline.set_state, Gst.State.NULL)

    # --- *** MODIFIED stop_stream (Synchronous State Change) *** ---
    def stop_stream(self, stream_key):
        pipeline_to_stop = None
        bus_to_clear = None
        key = -1
        try:
            try: key = int(stream_key)
            except (ValueError, TypeError): raise ValueError(f"Invalid stream identifier: '{stream_key}'. Must be a number.")

            with self.lock:
                if key not in self.active_streams:
                    self.logger.warning(f"Attempted to stop non-existent stream with key: {key}")
                    return False, f"Stream {key} not found."

                self.logger.info(f"Attempting to stop stream with key: {key}")
                stream_info = self.active_streams.pop(key) # Remove from active dict first
                pipeline_to_stop = stream_info.get('pipeline')
                bus_to_clear = stream_info.get('bus')

            if pipeline_to_stop:
                # Remove bus watch first
                if bus_to_clear:
                    try:
                        self.logger.debug(f"Removing signal watch from bus for stream {key}.")
                        bus_to_clear.remove_signal_watch()
                    except Exception as bus_e:
                        self.logger.warning(f"Error removing signal watch for stream {key}: {bus_e}")

                # *** Set state to NULL synchronously ***
                self.logger.info(f"Attempting synchronous pipeline state change to NULL for stream {key}.")
                # This call will block until the state change completes or fails.
                # Timeout is Gst.CLOCK_TIME_NONE (wait indefinitely), might need adjustment if it hangs.
                ret_null = pipeline_to_stop.set_state(Gst.State.NULL)
                # *** END Synchronous State Change ***

                if ret_null == Gst.StateChangeReturn.FAILURE:
                     self.logger.error(f"Failed to set pipeline state to NULL for stream {key}.")
                     # Can't do much more here, pipeline object might be unusable
                     # Log the object ID for reference?
                     self.logger.error(f"Pipeline object ref: {pipeline_to_stop}")
                     return False, f"Failed to set pipeline to NULL for stream {key}."
                elif ret_null == Gst.StateChangeReturn.ASYNC:
                    # This *shouldn't* happen with a synchronous call to NULL usually, but log if it does.
                    self.logger.warning(f"State change to NULL returned ASYNC for stream {key} (unexpected). Relying on eventual cleanup.")
                    return True, f"Stream {key} stop initiated (async NULL)." # Indicate uncertainty
                elif ret_null == Gst.StateChangeReturn.SUCCESS:
                     self.logger.info(f"Successfully set pipeline state to NULL for stream {key}.")
                     # Consider adding a very small sleep just in case resources aren't *immediately* free
                     # time.sleep(0.1)
                     return True, f"Stream {key} stopped successfully."
                else:
                     # Handle other potential return values like NO_PREROLL if needed
                     self.logger.warning(f"Setting pipeline state to NULL for stream {key} returned: {ret_null.value_nick}")
                     return True, f"Stream {key} stop attempt finished with state: {ret_null.value_nick}"

            else:
                self.logger.warning(f"Stream {key} was active but no pipeline object found in stored info.")
                return False, f"Stream {key} active but pipeline missing."
        except ValueError as e: self.logger.error(f"Stream stop validation error: {str(e)}"); return False, str(e)
        except Exception as e:
            self.logger.error(f"Unexpected error stopping stream {stream_key}: {str(e)}", exc_info=True)
            # Ensure cleanup attempt even on error
            if pipeline_to_stop:
                try: pipeline_to_stop.set_state(Gst.State.NULL) # Try sync cleanup on error too
                except: pass # Ignore errors during cleanup on error
            # Ensure removed from dict if error occurred after pop
            with self.lock:
                 if isinstance(key, int) and key > 0 and key in self.active_streams:
                      del self.active_streams[key] # Should already be popped, but double-check
            return False, f"An unexpected error occurred stopping stream: {str(e)}"
    # --- *** END MODIFIED stop_stream *** ---

    # --- Information Retrieval Methods (Keep as is from V10) ---
    def get_active_streams(self):
        # (Keep existing implementation)
        with self.lock:
            streams_copy = {}
            for k, v in self.active_streams.items():
                 try: streams_copy[k] = { 'config': v.get('config', {}).copy(), 'file_path': v.get('file_path'), 'srt_uri': v.get('srt_uri'), 'mode': v.get('mode'), 'start_time': v.get('start_time'), 'connection_status': v.get('connection_status'), 'connected_client': v.get('connected_client'), 'socket_id': v.get('socket_id'), 'target': v.get('target') }
                 except Exception as copy_e: self.logger.error(f"Error copying stream info for key {k}: {copy_e}"); continue
        sanitized_result = {}
        for key, stream_info in streams_copy.items():
            try:
                config = stream_info.get('config', {}); data = { 'key': key, 'file_path': stream_info.get('file_path', 'N/A'), 'mode': stream_info.get('mode', 'unknown'), 'latency': config.get('latency', DVB_STANDARD_CONFIG.get('srt_latency', 300)), 'overhead_bandwidth': config.get('overhead_bandwidth', 25), 'encryption': config.get('encryption', 'none'), 'passphrase_set': bool(config.get('passphrase')) and config.get('encryption', 'none') != 'none', 'qos_enabled': config.get('qos', False), 'srt_uri': stream_info.get('srt_uri', ''), 'connection_status': stream_info.get('connection_status', 'Unknown'), 'connected_client': self._extract_ip_from_socket_address(stream_info.get('connected_client')), 'target': stream_info.get('target', None), 'start_time': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(stream_info.get('start_time', 0))) if stream_info.get('start_time') else 'N/A' }; sanitized_result[key] = data
            except Exception as e: self.logger.error(f"Error sanitizing stream data for key {key}: {e}"); sanitized_result[key] = {'key': key, 'error': 'Failed to retrieve full stream details'}; continue
        return sanitized_result

    def _extract_stats_from_gstruct(self, stats_struct):
         # (Keep existing V9 implementation)
        result = {}
        raw_stats_string_for_debug = "N/A"
        if not stats_struct or not isinstance(stats_struct, Gst.Structure):
            self.logger.warning("Invalid Gst.Structure passed to _extract_stats_from_gstruct.")
            return result
        try:
            raw_stats_string_for_debug = stats_struct.to_string()
            if not raw_stats_string_for_debug:
                self.logger.warning("Gst.Structure.to_string() returned empty string.")
                return result
            def parse_value(value_str, value_type): # Nested helper
                value_type = value_type.lower(); value_str = value_str.strip()
                if value_str.endswith('\\'): value_str = value_str[:-1]
                is_quoted = value_str.startswith('"') and value_str.endswith('"')
                if is_quoted: value_str_unquoted = value_str[1:-1].replace('\\"', '"').replace('\\\\', '\\')
                else: value_str_unquoted = value_str
                if value_str_unquoted == "NULL": return None
                if value_str_unquoted == "TRUE": return True
                if value_str_unquoted == "FALSE": return False
                if 'int' in value_type:
                    try: return int(value_str_unquoted)
                    except ValueError: self.logger.warning(f"StatsParse: Failed int conversion: '{value_str_unquoted}'"); return 0
                if 'double' in value_type or 'float' in value_type:
                    try: return round(float(value_str_unquoted), 2)
                    except ValueError: self.logger.warning(f"StatsParse: Failed float conversion: '{value_str_unquoted}'"); return 0.0
                return value_str_unquoted
            inner_listener_pattern = re.compile(r'([a-zA-Z0-9\-]+)\s*\\\=\s*\\\(([^)]+)\\\)' r'("(?:[^"\\]|\\.)*"|[^,]+)')
            top_level_listener_pattern = re.compile(r'([a-zA-Z0-9\-]+)\s*=\s*\(([^)]+)\)' r'("(?:[^"\\]|\\.)*"|[^;]+)')
            caller_pattern = re.compile(r'([a-zA-Z0-9\-]+)\s*=\s*\(([^)]+)\)' r'("(?:[^"\\]|\\.)*"|[^,;]+)')
            def parse_with_finditer(text_to_parse, target_dict, pattern, context): # Nested helper
                processed_keys = set(target_dict.keys())
                segments_found = 0
                for match in pattern.finditer(text_to_parse):
                    segments_found += 1
                    key_raw, value_type, value_part = match.groups()[:3]
                    key = key_raw.replace('-', '_')
                    if key not in processed_keys:
                        value = parse_value(value_part, value_type)
                        target_dict[key] = value
                        processed_keys.add(key)
            payload_str = raw_stats_string_for_debug
            if ',' in payload_str: payload_str = payload_str.split(',', 1)[1]
            payload_str = payload_str.strip(';{} ')
            if 'callers=' in payload_str: # Listener format
                inner_kv_string = None
                callers_match = re.search(r'callers=\(GValueArray\)<(.*?)>', payload_str, re.DOTALL)
                top_level_str = payload_str
                if callers_match:
                    callers_content = callers_match.group(1).strip()
                    inner_struct_match = re.match(r'\s*"(?:application/x-srt-statistics\\,)?(.*?)\s*;?"\s*', callers_content, re.DOTALL)
                    if inner_struct_match:
                        inner_kv_string_escaped = inner_struct_match.group(1)
                        inner_kv_string = inner_kv_string_escaped.replace('\\,', ',').replace('\\"', '"').replace('\\\\', '\\').strip().lstrip('\\ ')
                        top_level_str = payload_str[:callers_match.start()] + payload_str[callers_match.end():]
                        top_level_str = top_level_str.strip('; ,')
                    else: self.logger.warning(f"StatsParse: Could not extract inner kv string from callers: {callers_content}")
                else: self.logger.warning("StatsParse: 'callers=' found but regex failed to extract content.")
                if inner_kv_string: parse_with_finditer(inner_kv_string, result, inner_listener_pattern, "InnerListener")
                parse_with_finditer(top_level_str, result, top_level_listener_pattern, "TopLevelListener")
            else: # Caller format
                parse_with_finditer(payload_str, result, caller_pattern, "Caller")
            final_key_map = {'bitrate_mbps': ['send_rate_mbps'], 'rtt_ms': ['rtt_ms', 'link_rtt'], 'loss_rate': ['pkt_loss_rate'],'packets_sent_total': ['packets_sent', 'pkt_sent_total'], 'packets_lost_total': ['packets_sent_lost', 'pkt_lost_total'],'packets_retransmitted_total': ['packets_retransmitted', 'pkt_retransmitted_total'], 'bytes_sent_total': ['bytes_sent_total'],'estimated_bandwidth_mbps': ['bandwidth_mbps', 'link_bandwidth'], 'packets_received_total': ['packets_received', 'pkt_received_total'],'packets_received_lost': ['packets_received_lost'], 'packets_received_retransmitted': ['packets_received_retransmitted'],'packets_received_dropped': ['packets_received_dropped'], 'bytes_sent': ['bytes_sent'], 'bytes_received': ['bytes_received'],'bytes_retransmitted': ['bytes_retransmitted'], 'bytes_sent_dropped': ['bytes_sent_dropped'], 'bytes_received_lost': ['bytes_received_lost'],'packet_ack_received': ['packet_ack_received'], 'packet_nack_received': ['packet_nack_received'], 'packet_ack_sent': ['packet_ack_sent'],'packet_nack_sent': ['packet_nack_sent'], 'send_buffer_level_ms': ['snd_buf_ms'], 'recv_buffer_level_ms': ['rcv_buf_ms'],'flow_window': ['flow_wnd', 'snd_flow_wnd'], 'negotiated_latency_ms': ['negotiated_latency_ms']}
            final_result = {'bitrate_mbps': 0.0, 'rtt_ms': 0.0, 'loss_rate': 0.0, 'packets_sent_total': 0, 'packets_lost_total': 0,'packets_retransmitted_total': 0, 'bytes_sent_total': 0, 'packet_loss_percent': 0.0, 'estimated_bandwidth_mbps': 0.0,'packets_received_total': 0, 'packets_received_lost': 0, 'packets_received_retransmitted': 0,'packets_received_dropped': 0, 'bytes_sent': 0, 'bytes_received': 0, 'bytes_retransmitted': 0,'bytes_sent_dropped': 0, 'bytes_received_lost': 0, 'packet_ack_received': 0, 'packet_nack_received': 0,'packet_ack_sent': 0, 'packet_nack_sent': 0, 'send_buffer_level_ms': 0, 'recv_buffer_level_ms': 0, 'flow_window': 0,'negotiated_latency_ms': 0}
            for final_key, source_keys in final_key_map.items():
                for source_key in source_keys:
                    if source_key in result: final_result[final_key] = result[source_key]; break
            sent = final_result.get('packets_sent_total', 0); lost = final_result.get('packets_lost_total', 0)
            if isinstance(sent, (int, float)) and isinstance(lost, (int, float)) and sent > 0: final_result['packet_loss_percent'] = round((lost / sent) * 100, 2)
            else: final_result['packet_loss_percent'] = 0.0
            for key, value in result.items(): final_result.setdefault(key, value)
            return final_result
        except Exception as e:
            self.logger.error(f"CRITICAL Error parsing SRT statistics structure: {str(e)}", exc_info=True)
            return {'error': f"Failed to parse stats: {str(e)}", 'raw_string': raw_stats_string_for_debug}

    def get_stream_statistics(self, stream_key):
        # (Keep existing implementation)
        pipeline = None; stream_info_copy = None
        try:
            key = int(stream_key)
            with self.lock:
                if key not in self.active_streams: self.logger.warning(f"Statistics requested for non-existent stream key: {key}"); return None
                stream_info = self.active_streams[key]; pipeline = stream_info.get('pipeline')
                stream_info_copy = { 'connection_status': stream_info.get('connection_status', 'Unknown'), 'connected_client': stream_info.get('connected_client'), 'start_time': stream_info.get('start_time', time.time()), 'config': stream_info.get('config', {}).copy() }
            if stream_info_copy is None: self.logger.error(f"Failed to copy stream info for active stream {key}"); return None
            stats = { 'connection_status': stream_info_copy.get('connection_status', 'Unknown'), 'connected_client': self._extract_ip_from_socket_address(stream_info_copy.get('connected_client')), 'uptime': self._format_uptime(time.time() - stream_info_copy.get('start_time', time.time())), 'last_updated': time.time(), 'config': stream_info_copy.get('config', {}) }
            if pipeline:
                sink_name = f"srtsink_{key}"; srtsink = pipeline.get_by_name(sink_name)
                if srtsink:
                    try:
                        stats_struct = srtsink.get_property('stats')
                        if stats_struct and isinstance(stats_struct, Gst.Structure):
                            parsed_stats = self._extract_stats_from_gstruct(stats_struct)
                            if 'error' in parsed_stats: self.logger.warning(f"Stats parsing resulted in an error for stream {key}: {parsed_stats['error']}")
                            stats.update(parsed_stats)
                        else: self.logger.warning(f"srtsink 'stats' property was null or not a Gst.Structure for stream {key}.")
                    except Exception as e: self.logger.error(f"Error getting or parsing 'stats' property for stream {key}: {str(e)}", exc_info=True); stats['error'] = f"Failed to retrieve/parse GStreamer stats: {str(e)}"
                else: self.logger.warning(f"Could not find srtsink element '{sink_name}' for stream {key} during stats fetch."); stats['error'] = f"srtsink element '{sink_name}' not found."
            else: self.logger.warning(f"Pipeline object missing for active stream {key} during stats fetch."); stats['error'] = "Pipeline object not found for active stream."
            return stats
        except ValueError as e: self.logger.error(f"Get statistics validation error for key '{stream_key}': {str(e)}"); return None
        except Exception as e: self.logger.error(f"Unexpected error getting statistics for stream {stream_key}: {str(e)}", exc_info=True); return None

    def _format_uptime(self, seconds):
         # (Keep existing implementation)
        try:
            seconds_int = int(seconds);
            if seconds_int < 0: return "0s";
            days, remainder_d = divmod(seconds_int, 86400); hours, remainder_h = divmod(remainder_d, 3600); minutes, sec = divmod(remainder_h, 60)
            parts = [];
            if days > 0: parts.append(f"{days}d")
            if hours > 0: parts.append(f"{hours}h")
            if minutes > 0: parts.append(f"{minutes}m")
            if sec > 0 or not parts: parts.append(f"{sec}s")
            return " ".join(parts) if parts else "0s"
        except Exception as e: self.logger.error(f"Error formatting uptime from seconds ({seconds}): {str(e)}"); return "Error"

    def get_file_info(self, file_path):
         # (Keep existing implementation)
        try: cmd = ['ffprobe', '-v', 'error', '-show_format', '-show_streams', '-of', 'json', file_path]; result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30); return json.loads(result.stdout)
        except FileNotFoundError:
            self.logger.warning("ffprobe not found. Attempting to use mediainfo...")
            try: cmd = ['mediainfo', '--Output=JSON', file_path]; result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=45); mediainfo_output = json.loads(result.stdout); return mediainfo_output.get('media', mediainfo_output)
            except FileNotFoundError: self.logger.error("mediainfo command not found either. Cannot get file info."); return {"error": "Failed to get file info: Neither ffprobe nor mediainfo found."}
            except Exception as e: self.logger.error(f"Error running mediainfo for '{file_path}': {str(e)}", exc_info=True); return {"error": f"Failed to get file info using mediainfo: {str(e)}"}
        except Exception as e: self.logger.error(f"Error running ffprobe for '{file_path}': {str(e)}", exc_info=True); return {"error": f"Failed to get file info using ffprobe: {str(e)}"}

    def get_debug_info(self, stream_key):
        # (Keep existing implementation)
        stream_info_copy = None; pipeline = None
        try:
            key = int(stream_key)
            with self.lock:
                if key not in self.active_streams: return {"error": f"Stream {key} not found"}
                stream_info = self.active_streams[key]; pipeline = stream_info.get('pipeline')
                stream_info_copy = { 'mode': stream_info.get('mode', '?'), 'file_path': stream_info.get('file_path'), 'target': stream_info.get('target'), 'srt_uri': stream_info.get('srt_uri'), 'connection_status': stream_info.get('connection_status'), 'connected_client': stream_info.get('connected_client'), 'start_time': stream_info.get('start_time', 0), 'config': stream_info.get('config', {}).copy(), 'connection_history': stream_info.get('connection_history', []).copy() }
            if not stream_info_copy: return {"error": f"Failed to retrieve info for stream {key}"}
            debug_info = { "stream_key": key, "mode": stream_info_copy.get('mode', '?'), "file_path": stream_info_copy.get('file_path'), "target": stream_info_copy.get('target'), "uri": stream_info_copy.get('srt_uri'), "status": stream_info_copy.get('connection_status'), "client_ip": self._extract_ip_from_socket_address(stream_info_copy.get('connected_client')), "uptime": self._format_uptime(time.time() - stream_info_copy.get('start_time', time.time())), "config": self._sanitize_for_json(stream_info_copy.get('config', {})), "connection_history": self._sanitize_for_json(stream_info_copy.get('connection_history', [])) }
            if pipeline:
                sink_name = f"srtsink_{key}"; srtsink = pipeline.get_by_name(sink_name)
                if srtsink:
                    try:
                        stats_struct = srtsink.get_property('stats')
                        if stats_struct and isinstance(stats_struct, Gst.Structure):
                            debug_info["raw_stats_string"] = stats_struct.to_string(); parsed = self._extract_stats_from_gstruct(stats_struct); debug_info["parsed_stats"] = parsed;
                            if 'error' in parsed: debug_info["parsing_error"] = parsed['error']
                        else: debug_info["stats_error"] = "Could not retrieve stats (null or not Gst.Structure)"
                    except Exception as e: debug_info["stats_error"] = f"Error getting/parsing stats property: {str(e)}"
                else: debug_info["stats_error"] = f"srtsink element '{sink_name}' not found in pipeline."
            else: debug_info["stats_error"] = "Pipeline object not found for active stream."
            return debug_info
        except ValueError as e: return {"error": str(e)}
        except Exception as e: self.logger.error(f"Unexpected error getting debug info for stream {stream_key}: {str(e)}", exc_info=True); return {"error": f"An unexpected error occurred: {str(e)}"}

    # --- Shutdown Method (Keep as is from V10) ---
    def shutdown(self):
        self.logger.info("Shutting down StreamManager...");
        with self.lock: active_keys = list(self.active_streams.keys()); self.logger.info(f"Stopping {len(active_keys)} active streams...");
        # Use a copy of keys to avoid issues if stop_stream modifies the dict further
        keys_to_stop = list(active_keys)
        for key in keys_to_stop:
             self.logger.info(f"Initiating shutdown for stream {key}...")
             self.stop_stream(key)
        # Wait a bit longer after initiating all stops
        final_wait = 1.5
        self.logger.info(f"Waiting {final_wait} seconds after initiating all stream stops...")
        time.sleep(final_wait)
        if self.mainloop.is_running(): self.logger.info("Quitting GLib MainLoop..."); self.mainloop.quit()
        if self.thread.is_alive(): self.logger.info("Waiting for main loop thread to join..."); self.thread.join(timeout=5.0);
        if self.thread.is_alive(): self.logger.warning("Main loop thread did not join!")
        self.logger.info("StreamManager shutdown complete.")
