# /opt/srt-streamer-enhanced/app/routes.py
# Defines the URL routes and view functions for the Flask application.
# Based on user-provided working version, with enhanced network test routes added back.

from flask import (
    render_template, request, jsonify, send_from_directory,
    redirect, url_for, flash, current_app as app, session # session might be needed for flash messages
)
# Import ALL needed forms from the MERGED app/forms.py
from app.forms import (
    StreamForm, CallerForm, NetworkTestForm, MediaUploadForm, SettingsForm
)
from app.utils import get_system_info
from app.network_test import NetworkTester # Uses the updated network_test.py
import os
import logging
from datetime import datetime
import json # For potentially handling JSON errors

logger = logging.getLogger(__name__)

# Initialize network tester (handle potential errors)
try:
    network_tester = NetworkTester()
    logger.info("NetworkTester initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize NetworkTester: {e}", exc_info=True)
    network_tester = None # Important: Allows app to run, network test will be degraded

# Wrap route definitions in a function called by __init__
def register_routes(app_instance):

    # --- Routes from user's working version (SRT, Media, Details) ---

    @app_instance.route('/')
    def index():
        """ Renders the main dashboard page with listener form and active streams. """
        form = StreamForm() # Form for starting Listener streams
        error_message = request.args.get('error') # Get potential error from redirect

        # Apply settings from network test redirect if present
        if request.args.get('apply_network_test'):
            try:
                latency_arg = request.args.get('latency')
                overhead_arg = request.args.get('overhead')
                applied_settings = False
                if latency_arg is not None:
                    latency_val = int(latency_arg)
                    if 20 <= latency_val <= 8000: form.latency.data = latency_val; applied_settings = True
                    else: logger.warning(f"Latency value from URL ({latency_val}) out of range (20-8000)."); flash(f"Latency value ({latency_val}ms) invalid.", 'warning')
                if overhead_arg is not None:
                    overhead_val = int(overhead_arg)
                    if 1 <= overhead_val <= 99: form.overhead_bandwidth.data = overhead_val; applied_settings = True
                    else: logger.warning(f"Overhead value from URL ({overhead_val}) out of range (1-99)."); flash(f"Overhead value ({overhead_val}%) invalid.", 'warning')

                if applied_settings:
                    flash(f"Network test settings applied: Latency={form.latency.data}ms, Overhead={form.overhead_bandwidth.data}%", 'success')
                # Clean URL after applying settings (optional, using JS history is cleaner)
                # Consider removing params via JS on the frontend after applying if desired
            except (ValueError, TypeError) as e: logger.error(f"Failed to apply network test settings from URL: Invalid value - {e}"); flash(f"Error applying network settings: Invalid value provided.", 'danger')
            except Exception as e: logger.error(f"Unexpected error applying network test settings: {str(e)}"); flash("An unexpected error occurred while applying network settings.", 'danger')

        system_info = get_system_info()
        active_streams = app_instance.stream_manager.get_active_streams()
        return render_template('index.html',
                               form=form,
                               system_info=system_info,
                               active_streams=active_streams,
                               error=error_message)

    @app_instance.route("/start_listener_stream", methods=["POST"])
    def start_listener_stream():
        """ Handles submission of the Listener stream form from the index page. """
        form = StreamForm()
        system_info = get_system_info() # Needed for re-rendering on error
        active_streams = app_instance.stream_manager.get_active_streams() # Needed for re-rendering

        if form.validate_on_submit():
            # Validate file path securely
            try:
                file_to_check = form.file_path.data; file_path = os.path.abspath(os.path.join(app_instance.stream_manager.media_folder, file_to_check)); media_dir = os.path.abspath(app_instance.stream_manager.media_folder)
                if not file_to_check or not file_path.startswith(media_dir + os.sep) or not os.path.isfile(file_path): raise ValueError("Invalid/missing file path or not within media folder")
            except Exception as e: flash(f"Invalid media file: {e}", 'danger'); return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=str(e))

            # Build config dictionary including 'qos'
            config = { 'port': form.port.data, 'latency': form.latency.data, 'overhead_bandwidth': form.overhead_bandwidth.data, 'mode': 'listener', 'encryption': form.encryption.data, 'passphrase': form.passphrase.data, 'qos': form.qos.data, 'target_address': None, 'dvb_compliant': True }
            logger.info(f"Attempting to start LISTENER stream with config: {config}")

            success, message = app_instance.stream_manager.start_stream(file_path, config)
            if success: logger.info(f"Listener stream start initiated: {message}"); flash(f"Listener stream started successfully on port {config.get('port', 'N/A')}.", 'success'); return redirect(url_for('index'))
            else: logger.error(f"Listener stream start failed: {message}"); flash(f"Failed to start listener stream: {message}", 'danger'); return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=message)
        else:
            flash('Please correct the errors in the listener configuration form.', 'warning'); return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=None)

    @app_instance.route('/caller', methods=['GET', 'POST'])
    def caller_page():
        """ Renders the Caller stream configuration page and handles form submission. """
        form = CallerForm()
        error_message = None

        if form.validate_on_submit():
            # Validate file path securely
            try:
                file_to_check = form.file_path.data; file_path = os.path.abspath(os.path.join(app_instance.stream_manager.media_folder, file_to_check)); media_dir = os.path.abspath(app_instance.stream_manager.media_folder)
                if not file_to_check or not file_path.startswith(media_dir + os.sep) or not os.path.isfile(file_path): raise ValueError("Invalid/missing file path or not within media folder")
            except Exception as e: error_message = f"Invalid media file selected: {e}"; return render_template('caller.html', form=form, error=error_message)

            # Build config dictionary including 'qos'
            config = { 'mode': 'caller', 'target_address': form.target_address.data, 'target_port': form.target_port.data, 'latency': form.latency.data, 'overhead_bandwidth': form.overhead_bandwidth.data, 'encryption': form.encryption.data, 'passphrase': form.passphrase.data, 'qos': form.qos.data, 'dvb_compliant': True }
            logger.info(f"Attempting to start CALLER stream with config: {config}")

            success, message = app_instance.stream_manager.start_stream(file_path, config, use_target_port_as_key=True)
            if success: logger.info(f"Caller stream start initiated: {message}"); flash(f"Caller stream to {config.get('target_address', 'N/A')}:{config.get('target_port', 'N/A')} started.", 'success'); return redirect(url_for('index'))
            else: logger.error(f"Caller stream start failed: {message}"); error_message = f"Failed to start caller stream: {message}"; return render_template('caller.html', form=form, error=error_message)
        return render_template('caller.html', form=form, error=error_message)

    @app_instance.route("/stop_stream/<stream_key>", methods=["POST"])
    def stop_stream(stream_key):
        """ Stops an active SRT stream identified by its key (port or target_port). """
        try: key_int = int(stream_key); assert 0 < key_int < 65536
        except: flash("Invalid stream identifier.", 'danger'); return redirect(url_for('index'))
        success, message = app_instance.stream_manager.stop_stream(stream_key)
        if success: logger.info(f"Stream stopped via UI: {message}"); flash(f"Stream ({stream_key}) stopped successfully.", 'success')
        else: logger.error(f"Stream stop failed via UI: {message}"); flash(f"Failed to stop stream ({stream_key}): {message}", 'danger')
        return redirect(url_for('index'))

    @app_instance.route("/media")
    def list_media():
        """ API endpoint to list available .ts files in the media folder. """
        media_files = []; media_dir = app_instance.stream_manager.media_folder
        try:
            if not os.path.isdir(media_dir): logger.error(f"Media directory not found: {media_dir}"); return jsonify({"error": "Media directory configuration error"}), 500
            for file in os.listdir(media_dir):
                if file.startswith('.') or not file.lower().endswith('.ts'): continue
                try:
                    file_path = os.path.join(media_dir, file);
                    if os.path.isfile(file_path): media_files.append({'name': file, 'size': os.path.getsize(file_path)})
                except Exception as file_e: logger.warning(f"Could not get info for file '{file}': {file_e}")
            media_files.sort(key=lambda x: x['name'])
        except Exception as e: logger.error(f"Failed to list media in '{media_dir}': {str(e)}"); return jsonify({"error": "Failed to list media files"}), 500
        return jsonify(media_files)

    @app_instance.route("/media_info/<path:filename>")
    def media_info(filename):
        """ Displays detailed media information for a specific file. """
        if '..' in filename or filename.startswith('/') or not filename.lower().endswith('.ts'): flash("Invalid or disallowed filename.", 'danger'); return redirect(url_for('index'))
        try:
            media_dir = os.path.abspath(app_instance.stream_manager.media_folder); file_path = os.path.abspath(os.path.join(media_dir, filename))
            if not file_path.startswith(media_dir + os.sep) or not os.path.isfile(file_path): raise FileNotFoundError("Media file not found or outside allowed directory.")
        except Exception as e: flash(f"Cannot access file '{filename}': {e}", 'danger'); return redirect(url_for('index'))
        info = app_instance.stream_manager.get_file_info(file_path); dummy_form = StreamForm()
        return render_template('media_info.html', filename=filename, info=info, form=dummy_form)

    @app_instance.route("/stream/<stream_key>")
    def stream_details(stream_key):
        """ Displays the detailed statistics page for a specific active stream. """
        try: key = int(stream_key); assert 0 < key < 65536
        except: flash("Invalid stream identifier format.", 'danger'); return redirect(url_for('index'))
        stream_data = app_instance.stream_manager.get_active_streams().get(key)
        if not stream_data: flash(f"Stream ({key}) not found or has stopped.", 'warning'); return redirect(url_for('index'))
        form = StreamForm()
        return render_template('stream_details.html', stream_key=key, stream=stream_data, form=form)

    # --- API Endpoints (From User's Working Version + Enhanced Network Test) ---

    @app_instance.route("/get_active_streams")
    def get_active_streams():
        """ API endpoint to get a list of currently active streams and their config. """
        try: streams = app_instance.stream_manager.get_active_streams(); return jsonify(streams)
        except Exception as e: logger.error(f"Error getting active streams via API: {e}", exc_info=True); return jsonify({"error": "Could not retrieve stream list"}), 500

    @app_instance.route("/api/stats/<stream_key>")
    def get_stats(stream_key):
        """ API endpoint to get detailed statistics for a specific stream. """
        try: key = int(stream_key); assert 0 < key < 65536
        except: return jsonify({'error': f'Invalid stream key format: {stream_key}'}), 400
        stats = app_instance.stream_manager.get_stream_statistics(stream_key)
        if stats: return jsonify(stats)
        else: return jsonify({'error': f'Stream ({stream_key}) not found or error getting stats'}), 404

    @app_instance.route('/api/debug/<stream_key>')
    def get_debug_info(stream_key):
        """ API endpoint to get raw debug info for a stream. """
        try: key = int(stream_key); assert 0 < key < 65536
        except: return jsonify({'error': f'Invalid stream key format: {stream_key}'}), 400
        debug_info = app_instance.stream_manager.get_debug_info(stream_key)
        if debug_info is None: return jsonify({'error': f'Error fetching debug info for stream ({stream_key})'}), 500
        if 'error' in debug_info: status_code = 404 if 'not found' in debug_info['error'].lower() else 500; return jsonify(debug_info), status_code
        try: return jsonify(debug_info)
        except TypeError as e: logger.error(f"Failed to serialize debug info for stream {stream_key}: {e}"); return jsonify({"error": f"Could not serialize debug information for stream {stream_key}"}), 500

    @app_instance.route("/system_info")
    def system_info():
        """ API endpoint to get current system resource usage and time. """
        try: info = get_system_info(); return jsonify(info)
        except Exception as e: logger.error(f"Error getting system info via API: {e}", exc_info=True); return jsonify({"error": "Could not retrieve system info"}), 500

    @app_instance.route('/health')
    def health_check():
        """ Basic health check endpoint for monitoring. """
        return "OK", 200

    # --- *** ADDED BACK Enhanced Network Test Routes *** ---

    @app_instance.route('/network_test') # Route for loading the page
    def network_test_page():
        """ Renders the network test configuration page (Enhanced Version). """
        form = NetworkTestForm() # Use the ENHANCED form from merged forms.py
        location_info = None
        regions = []

        if network_tester:
            try:
                location_info = network_tester.get_external_ip_and_location()
                regions = network_tester.get_server_regions()
                # Populate region choices dynamically
                form.region.choices = [('', '-- Select Region --')] + [(r, r) for r in regions if r]
                logger.info(f"Populated network test regions: {regions}")
            except AttributeError as ae:
                logger.error(f"NetworkTester missing method used by network_test_page: {ae}", exc_info=True)
                flash("Network testing service is partially unavailable (code error).", "danger")
            except Exception as e:
                logger.error(f"Error getting data for network test page: {e}", exc_info=True)
                flash("Error preparing network test page data. Check logs.", "danger")
        else:
            flash("Network testing service is not available.", "warning")
            logger.warning("NetworkTester object is None in network_test_page route.")

        return render_template('network_test.html',
                               form=form, # Pass the enhanced form instance
                               location_info=location_info,
                               regions=regions)

    @app_instance.route('/api/network_test', methods=['POST']) # API endpoint for AJAX
    def network_test_api():
        """ API endpoint to run a network test (called via AJAX - Enhanced Version). """
        # Instantiate ENHANCED form using request.form data from AJAX
        form = NetworkTestForm(request.form)

        # Dynamically populate region choices BEFORE validation
        if network_tester:
            try:
                regions = network_tester.get_server_regions()
                form.region.choices = [('', '-- Select Region --')] + [(r, r) for r in regions if r]
            except Exception as e:
                 logger.error(f"Failed to populate region choices during API validation: {e}")
                 form.region.choices = [('', '-- Select Region --')]

        # Validate the enhanced form data
        if form.validate():
            try:
                if not network_tester:
                    logger.error("Network test API called but NetworkTester is not initialized.")
                    return jsonify({"error": "Network testing service unavailable."}), 503

                location_info = network_tester.get_external_ip_and_location()
                mode = form.mode.data
                region = form.region.data
                manual_host = form.manual_host.data or None
                manual_port = form.manual_port.data
                manual_protocol = form.manual_protocol.data # Get the selected protocol
                duration = form.duration.data
                bitrate = form.bitrate.data

                logger.info(f"Executing network test via API: mode={mode}, region={region}, manual_host={manual_host}, manual_port={manual_port}, manual_protocol={manual_protocol}, duration={duration}, bitrate={bitrate}")

                # Call the UPDATED run_network_test method from network_test.py
                result = network_tester.run_network_test(
                    mode=mode,
                    region=region,
                    manual_host=manual_host,
                    manual_port=manual_port,
                    manual_protocol=manual_protocol, # Pass the protocol
                    duration=duration,
                    bitrate=bitrate,
                    location_info=location_info
                )

                if result is None:
                    result = network_tester.get_fallback_results("Test execution unexpectedly returned None.")

                logger.info(f"Network test API completed successfully.")
                return jsonify(result)

            except AttributeError as ae:
                logger.error(f"Network test API execution error: Missing method/attribute - {ae}", exc_info=True)
                return jsonify({"error": f"Test execution failed due to code error ({ae})"}), 500
            except Exception as e:
                logger.error(f"Network test API execution error: {str(e)}", exc_info=True)
                return jsonify({"error": f"Test execution failed: {str(e)}"}), 500
        else:
            # Enhanced Form validation failed
            logger.warning(f"Network test form validation failed: {form.errors}")
            error_details = {field: errors[0] for field, errors in form.errors.items() if field != 'csrf_token'}
            first_error_msg = next(iter(error_details.values()), "Invalid input")
            return jsonify({"error": f"Validation failed: {first_error_msg}", "details": error_details}), 400

    # --- End of register_routes function ---
