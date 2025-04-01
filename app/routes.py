# /opt/srt-streamer-enhanced/app/routes.py
# Defines the URL routes and view functions for the Flask application.
# Corrected version addressing AttributeError and ensuring region population.

from flask import (
    render_template, request, jsonify, send_from_directory,
    redirect, url_for, flash, current_app as app, session
)
from app.forms import (
    StreamForm, CallerForm, NetworkTestForm, MediaUploadForm, SettingsForm
)
from app.utils import get_system_info
from app.network_test import NetworkTester
import os
import logging
from datetime import datetime
import json

logger = logging.getLogger(__name__)

# Initialize network tester
try:
    network_tester = NetworkTester()
    logger.info("NetworkTester initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize NetworkTester: {e}", exc_info=True)
    network_tester = None

def register_routes(app_instance):

    # --- Existing Stream/Core Routes (Keep As Is - Assuming they are correct) ---

    @app_instance.route('/')
    def index():
        # ... (Keep existing index route logic as provided previously) ...
        form = StreamForm()
        error_message = request.args.get('error')
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
                if applied_settings: flash(f"Network test settings applied: Latency={form.latency.data}ms, Overhead={form.overhead_bandwidth.data}%", 'success')
            except (ValueError, TypeError) as e: logger.error(f"Failed to apply network test settings from URL: Invalid value - {e}"); flash(f"Error applying network settings: Invalid value.", 'danger')
            except Exception as e: logger.error(f"Unexpected error applying network test settings: {str(e)}"); flash("Unexpected error applying settings.", 'danger')
        system_info = get_system_info()
        active_streams = app_instance.stream_manager.get_active_streams()
        return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=error_message)

    @app_instance.route("/start_listener_stream", methods=["POST"])
    def start_listener_stream():
        # ... (Keep existing logic) ...
        form = StreamForm()
        system_info = get_system_info()
        active_streams = app_instance.stream_manager.get_active_streams()
        if form.validate_on_submit():
            try: # File validation
                 file_to_check = form.file_path.data; file_path = os.path.abspath(os.path.join(app_instance.stream_manager.media_folder, file_to_check)); media_dir = os.path.abspath(app_instance.stream_manager.media_folder)
                 if not file_to_check or not file_path.startswith(media_dir + os.sep) or not os.path.isfile(file_path): raise ValueError("Invalid/missing file")
            except Exception as e: flash(f"Invalid media file: {e}", 'danger'); return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=str(e))
            config = { 'port': form.port.data, 'latency': form.latency.data, 'overhead_bandwidth': form.overhead_bandwidth.data, 'mode': 'listener', 'encryption': form.encryption.data, 'passphrase': form.passphrase.data, 'qos': form.qos.data, 'target_address': None, 'dvb_compliant': True }
            success, message = app_instance.stream_manager.start_stream(file_path, config)
            if success: flash(f"Listener stream started on port {config.get('port', 'N/A')}.", 'success'); return redirect(url_for('index'))
            else: flash(f"Failed to start listener stream: {message}", 'danger'); return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=message)
        else: flash('Please correct errors in the listener form.', 'warning'); return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=None)

    @app_instance.route('/caller', methods=['GET', 'POST'])
    def caller_page():
         # ... (Keep existing logic) ...
        form = CallerForm(); error_message = None
        if form.validate_on_submit():
            try: # File validation
                file_to_check = form.file_path.data; file_path = os.path.abspath(os.path.join(app_instance.stream_manager.media_folder, file_to_check)); media_dir = os.path.abspath(app_instance.stream_manager.media_folder)
                if not file_to_check or not file_path.startswith(media_dir + os.sep) or not os.path.isfile(file_path): raise ValueError("Invalid/missing file")
            except Exception as e: error_message = f"Invalid media file: {e}"; return render_template('caller.html', form=form, error=error_message)
            config = { 'mode': 'caller', 'target_address': form.target_address.data, 'target_port': form.target_port.data, 'latency': form.latency.data, 'overhead_bandwidth': form.overhead_bandwidth.data, 'encryption': form.encryption.data, 'passphrase': form.passphrase.data, 'qos': form.qos.data, 'dvb_compliant': True }
            success, message = app_instance.stream_manager.start_stream(file_path, config, use_target_port_as_key=True)
            if success: flash(f"Caller stream to {config.get('target_address', 'N/A')}:{config.get('target_port', 'N/A')} started.", 'success'); return redirect(url_for('index'))
            else: error_message = f"Failed to start caller stream: {message}"; return render_template('caller.html', form=form, error=error_message)
        return render_template('caller.html', form=form, error=error_message)

    @app_instance.route("/stop_stream/<stream_key>", methods=["POST"])
    def stop_stream(stream_key):
         # ... (Keep existing logic) ...
        try: key_int = int(stream_key); assert 0 < key_int < 65536
        except: flash("Invalid stream identifier.", 'danger'); return redirect(url_for('index'))
        success, message = app_instance.stream_manager.stop_stream(stream_key)
        if success: flash(f"Stream ({stream_key}) stopped.", 'success')
        else: flash(f"Failed to stop stream ({stream_key}): {message}", 'danger')
        return redirect(url_for('index'))

    @app_instance.route("/media")
    def list_media():
         # ... (Keep existing logic) ...
        media_files = []; media_dir = app_instance.stream_manager.media_folder
        try:
             if not os.path.isdir(media_dir): return jsonify({"error": "Media directory configuration error"}), 500
             for file in os.listdir(media_dir):
                 if file.startswith('.') or not file.lower().endswith('.ts'): continue
                 try:
                     file_path = os.path.join(media_dir, file);
                     if os.path.isfile(file_path): media_files.append({'name': file, 'size': os.path.getsize(file_path)})
                 except Exception as file_e: logger.warning(f"Could not get info for file '{file}': {file_e}")
             media_files.sort(key=lambda x: x['name'])
        except Exception as e: logger.error(f"Failed to list media: {str(e)}"); return jsonify({"error": "Failed to list media files"}), 500
        return jsonify(media_files)

    @app_instance.route("/media_info/<path:filename>")
    def media_info(filename):
        # ... (Keep existing logic) ...
        if '..' in filename or filename.startswith('/') or not filename.lower().endswith('.ts'): flash("Invalid filename.", 'danger'); return redirect(url_for('index'))
        try:
             media_dir = os.path.abspath(app_instance.stream_manager.media_folder); file_path = os.path.abspath(os.path.join(media_dir, filename))
             if not file_path.startswith(media_dir + os.sep) or not os.path.isfile(file_path): raise FileNotFoundError("File not found/allowed.")
        except Exception as e: flash(f"Cannot access file '{filename}': {e}", 'danger'); return redirect(url_for('index'))
        info = app_instance.stream_manager.get_file_info(file_path); dummy_form = StreamForm()
        return render_template('media_info.html', filename=filename, info=info, form=dummy_form)

    @app_instance.route("/stream/<stream_key>")
    def stream_details(stream_key):
        # ... (Keep existing logic) ...
        try: key = int(stream_key); assert 0 < key < 65536
        except: flash("Invalid stream identifier.", 'danger'); return redirect(url_for('index'))
        stream_data = app_instance.stream_manager.get_active_streams().get(key)
        if not stream_data: flash(f"Stream ({key}) not found.", 'warning'); return redirect(url_for('index'))
        form = StreamForm(); return render_template('stream_details.html', stream_key=key, stream=stream_data, form=form)

    # --- Existing API Endpoints (Keep As Is) ---
    @app_instance.route("/get_active_streams")
    def get_active_streams():
        # ... (Keep existing logic) ...
        try: streams = app_instance.stream_manager.get_active_streams(); return jsonify(streams)
        except Exception as e: logger.error(f"API Error get_active_streams: {e}", exc_info=True); return jsonify({"error": "Failed"}), 500

    @app_instance.route("/api/stats/<stream_key>")
    def get_stats(stream_key):
        # ... (Keep existing logic) ...
        try: key = int(stream_key); assert 0 < key < 65536
        except: return jsonify({'error': f'Invalid stream key: {stream_key}'}), 400
        stats = app_instance.stream_manager.get_stream_statistics(stream_key)
        if stats: return jsonify(stats)
        else: return jsonify({'error': f'Stream ({stream_key}) not found or stats error'}), 404

    @app_instance.route('/api/debug/<stream_key>')
    def get_debug_info(stream_key):
        # ... (Keep existing logic) ...
        try: key = int(stream_key); assert 0 < key < 65536
        except: return jsonify({'error': f'Invalid stream key: {stream_key}'}), 400
        debug_info = app_instance.stream_manager.get_debug_info(stream_key)
        if debug_info is None: return jsonify({'error': f'Error fetching debug info for {stream_key}'}), 500
        if 'error' in debug_info: status_code = 404 if 'not found' in debug_info['error'].lower() else 500; return jsonify(debug_info), status_code
        try: return jsonify(debug_info)
        except TypeError as e: logger.error(f"Serialization error for debug info {stream_key}: {e}"); return jsonify({"error": "Serialization error"}), 500

    @app_instance.route("/system_info")
    def system_info():
        # ... (Keep existing logic) ...
        try: info = get_system_info(); return jsonify(info)
        except Exception as e: logger.error(f"API Error system_info: {e}", exc_info=True); return jsonify({"error": "Failed"}), 500

    @app_instance.route('/health')
    def health_check():
        return "OK", 200

    # --- === UPDATED Network Test Routes === ---

    @app_instance.route('/network_test') # Route for loading the page
    def network_test_page():
        """ Renders the network test configuration page. """
        form = NetworkTestForm() # Use the UPDATED form from forms.py
        location_info = None
        regions = []

        if network_tester:
            try:
                # Get location info (reads IP from file, calls API)
                location_info = network_tester.get_external_ip_and_location() # Doesn't need request obj
                regions = network_tester.get_server_regions()
                # Populate form choices dynamically (handle potential empty list)
                form.region.choices = [('', '-- Select Region --')] + [(r, r) for r in regions if r]
                logger.info(f"Populated network test regions: {regions}") # Log fetched regions
            except AttributeError as ae:
                logger.error(f"NetworkTester missing method used by network_test_page: {ae}", exc_info=True)
                flash("Network testing service is partially unavailable (code error).", "danger")
            except Exception as e:
                logger.error(f"Error getting data for network test page: {e}", exc_info=True)
                flash("Error preparing network test page data. Check logs.", "danger")
        else:
            flash("Network testing service is not available.", "warning")
            logger.warning("NetworkTester object is None in network_test_page route.")


        # Pass the form instance (with choices populated) and location_info
        return render_template('network_test.html',
                               form=form,
                               location_info=location_info,
                               regions=regions) # Pass regions again for template access if needed outside form

    @app_instance.route('/api/network_test', methods=['POST']) # API endpoint for AJAX
    def network_test_api():
        """ API endpoint to run a network test (called via AJAX). """
        # Instantiate the form using request.form data from AJAX
        form = NetworkTestForm(request.form)

        # Dynamically populate choices BEFORE validation for SelectField
        # This is crucial for the SelectField('region') validator to work
        if network_tester:
            try:
                regions = network_tester.get_server_regions()
                form.region.choices = [('', '-- Select Region --')] + [(r, r) for r in regions if r]
            except Exception as e:
                 logger.error(f"Failed to populate region choices during API validation: {e}")
                 # Allow validation to proceed, but region selection might fail validation if it was required
                 form.region.choices = [('', '-- Select Region --')] # Ensure choices is at least an empty list

        if form.validate(): # Use validate() for data submitted via non-browser form (like AJAX)
            try:
                if not network_tester:
                    logger.error("Network test API called but NetworkTester is not initialized.")
                    return jsonify({"error": "Network testing service unavailable."}), 503

                # Get location info - needed for 'closest' mode logic within run_network_test
                # Call it here as the request context is available if needed by underlying methods,
                # even though the current implementation reads from a file.
                location_info = network_tester.get_external_ip_and_location()

                # --- ** FIX for AttributeError ** ---
                # Access the correct form fields: manual_host and manual_port
                # Instead of the old 'target' field which no longer exists
                host_to_pass = form.manual_host.data or None # Use None if empty
                port_to_pass = form.manual_port.data # Already validated as Optional[int]

                # Call the UPDATED run_network_test method with all parameters
                result = network_tester.run_network_test(
                    mode=form.mode.data,
                    region=form.region.data,
                    manual_host=host_to_pass,     # Use the correct field
                    manual_port=port_to_pass,     # Use the correct field
                    duration=form.duration.data,
                    bitrate=form.bitrate.data,
                    location_info=location_info # Pass location info for 'closest' mode logic
                )
                # --- ** End FIX ** ---

                if result is None:
                    result = network_tester.get_fallback_results("Test execution returned None.")

                logger.info(f"Network test API completed. Returning JSON.")
                return jsonify(result)

            except AttributeError as ae:
                logger.error(f"Network test API execution error: Missing method/attribute - {ae}", exc_info=True)
                return jsonify({"error": f"Test execution failed: Code error ({ae})"}), 500
            except Exception as e:
                logger.error(f"Network test API execution error: {str(e)}", exc_info=True)
                return jsonify({"error": f"Test execution failed: {str(e)}"}), 500
        else:
            # Validation failed
            logger.warning(f"Network test API validation failed: {form.errors}")
            error_details = {field: errors[0] for field, errors in form.errors.items()}
            return jsonify({"error": "Validation failed", "details": error_details}), 400

    # --- End of register_routes function ---
