# /opt/srt-streamer-enhanced/app/routes.py
# Defines the URL routes and view functions for the Flask application.
# This version ensures all original routes are present and incorporates QoS handling.

from flask import (
    render_template, request, jsonify, send_from_directory,
    redirect, url_for, flash, current_app as app, session # session might be needed for flash messages
)
# Import ALL needed forms from app.forms
from app.forms import (
    StreamForm, CallerForm, NetworkTestForm, MediaUploadForm, SettingsForm # Ensure SettingsForm is imported if used
)
from app.utils import get_system_info
from app.network_test import NetworkTester # Assuming NetworkTester is correctly implemented
import os
import logging
from datetime import datetime
import json # For potentially handling JSON errors

logger = logging.getLogger(__name__)

# Initialize network tester (handle potential errors)
try:
    network_tester = NetworkTester()
except Exception as e:
     logger.error(f"Failed to initialize NetworkTester: {e}")
     network_tester = None

# Wrap route definitions in a function called by __init__
def register_routes(app_instance):

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
                    form.latency.data = int(latency_arg)
                    applied_settings = True
                if overhead_arg is not None:
                    # Ensure overhead is within the new 1-99 range if applied from URL
                    overhead_val = int(overhead_arg)
                    if 1 <= overhead_val <= 99:
                        form.overhead_bandwidth.data = overhead_val
                        applied_settings = True
                    else:
                        logger.warning(f"Overhead value from URL ({overhead_val}) out of range (1-99). Not applying.")
                        flash(f"Overhead value ({overhead_val}%) from network test is out of range (1-99). Please adjust manually.", 'warning')

                if applied_settings:
                    flash(f"Network test settings applied: Latency={form.latency.data}ms, Overhead={form.overhead_bandwidth.data}%", 'success')
            except (ValueError, TypeError) as e:
                logger.error(f"Failed to apply network test settings from URL: Invalid value - {e}")
                flash(f"Error applying network settings: Invalid value provided.", 'danger')
            except Exception as e:
                 logger.error(f"Unexpected error applying network test settings: {str(e)}")
                 flash("An unexpected error occurred while applying network settings.", 'danger')

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
            # Double-check mode just in case (should be 'listener' from hidden field or default)
            if form.mode.data and form.mode.data != 'listener':
                flash('Incorrect form submission for listener mode.', 'danger')
                return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=None)

            # Validate file path
            try:
                file_to_check = form.file_path.data
                if not file_to_check: raise ValueError("File path is empty.")
                # Construct absolute path within the allowed media folder
                file_path = os.path.abspath(os.path.join(app_instance.stream_manager.media_folder, file_to_check))
                media_dir = os.path.abspath(app_instance.stream_manager.media_folder)
                # Security check: Ensure the path is within the media folder
                if not file_path.startswith(media_dir + os.sep) and file_path != media_dir:
                     raise ValueError("Attempted path traversal.")
                if not os.path.isfile(file_path):
                    raise FileNotFoundError(f"File not found or not accessible: {file_path}")
            except (FileNotFoundError, ValueError) as e:
                flash(f"Invalid media file selected: {e}", 'danger')
                return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=str(e))
            except Exception as e:
                 flash(f"Error validating file path: {e}", 'danger')
                 return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=str(e))

            # *** Build config dictionary including 'qos' ***
            config = {
                'port': form.port.data,
                'latency': form.latency.data,
                'overhead_bandwidth': form.overhead_bandwidth.data,
                'mode': 'listener', # Enforce listener mode here
                'encryption': form.encryption.data,
                'passphrase': form.passphrase.data,
                'qos': form.qos.data,  # Pass the QoS boolean value from the form
                'target_address': None, # Listener doesn't have a target address
                'dvb_compliant': True # Mandatory DVB compliance
            }
            logger.info(f"Attempting to start LISTENER stream with config: {config}")

            # Start the stream via StreamManager
            success, message = app_instance.stream_manager.start_stream(file_path, config) # No use_target_port_as_key needed for listener

            if success:
                logger.info(f"Listener stream start initiated: {message}")
                flash(f"Listener stream started successfully on port {config.get('port', 'N/A')}.", 'success')
                return redirect(url_for('index')) # Redirect back to dashboard on success
            else:
                logger.error(f"Listener stream start failed: {message}")
                flash(f"Failed to start listener stream: {message}", 'danger')
                # Re-render index page with form errors and flash message
                return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=message)
        else:
            # Form validation failed
            flash('Please correct the errors in the listener configuration form.', 'warning')
            return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=None)

    @app_instance.route('/caller', methods=['GET', 'POST'])
    def caller_page():
        """ Renders the Caller stream configuration page and handles form submission. """
        form = CallerForm()
        error_message = None # Specific error for this page context

        if form.validate_on_submit():
            # Validate file path
            try:
                file_to_check = form.file_path.data
                if not file_to_check: raise ValueError("File path is empty.")
                # Construct absolute path within the allowed media folder
                file_path = os.path.abspath(os.path.join(app_instance.stream_manager.media_folder, file_to_check))
                media_dir = os.path.abspath(app_instance.stream_manager.media_folder)
                # Security check: Ensure the path is within the media folder
                if not file_path.startswith(media_dir + os.sep) and file_path != media_dir:
                     raise ValueError("Attempted path traversal.")
                if not os.path.isfile(file_path):
                    raise FileNotFoundError(f"File not found or not accessible: {file_path}")
            except (FileNotFoundError, ValueError) as e:
                error_message = f"Invalid media file selected: {e}"
                # Re-render caller page with the error
                return render_template('caller.html', form=form, error=error_message)
            except Exception as e:
                 error_message = f"Error validating file path: {e}"
                 return render_template('caller.html', form=form, error=error_message)

            # *** Build config dictionary including 'qos' ***
            config = {
                'mode': 'caller', # Enforce caller mode
                'target_address': form.target_address.data,
                'target_port': form.target_port.data, # Use target_port as key for caller
                'latency': form.latency.data,
                'overhead_bandwidth': form.overhead_bandwidth.data,
                'encryption': form.encryption.data,
                'passphrase': form.passphrase.data,
                'qos': form.qos.data, # Pass the QoS boolean value from the form
                'dvb_compliant': True # Mandatory DVB compliance
            }
            logger.info(f"Attempting to start CALLER stream with config: {config}")

            # Start the stream via StreamManager, using target port as the key
            success, message = app_instance.stream_manager.start_stream(file_path, config, use_target_port_as_key=True)

            if success:
                logger.info(f"Caller stream start initiated: {message}")
                flash(f"Caller stream to {config.get('target_address', 'N/A')}:{config.get('target_port', 'N/A')} started.", 'success')
                return redirect(url_for('index')) # Redirect to dashboard on success
            else:
                logger.error(f"Caller stream start failed: {message}")
                error_message = f"Failed to start caller stream: {message}"
                # Re-render caller page with the error message
                return render_template('caller.html', form=form, error=error_message)
        # Else (GET request or validation failed)
        # If validation failed, form.errors will be populated and displayed by the template
        return render_template('caller.html', form=form, error=error_message)

    @app_instance.route("/stop_stream/<stream_key>", methods=["POST"])
    def stop_stream(stream_key):
        """ Stops an active SRT stream identified by its key (port or target_port). """
        # Validate stream_key format (should be numeric port)
        try:
            key_int = int(stream_key)
            if not (0 < key_int < 65536):
                raise ValueError("Port number out of range")
        except (ValueError, TypeError):
             flash("Invalid stream identifier provided.", 'danger')
             return redirect(url_for('index'))

        success, message = app_instance.stream_manager.stop_stream(stream_key)
        if success:
            logger.info(f"Stream stopped via UI: {message}")
            flash(f"Stream ({stream_key}) stopped successfully.", 'success')
        else:
            logger.error(f"Stream stop failed via UI: {message}")
            flash(f"Failed to stop stream ({stream_key}): {message}", 'danger')
        return redirect(url_for('index')) # Redirect back to dashboard

    @app_instance.route("/media")
    def list_media():
        """ API endpoint to list available .ts files in the media folder. """
        media_files = []
        media_dir = app_instance.stream_manager.media_folder
        try:
            if not os.path.isdir(media_dir):
                logger.error(f"Media directory not found: {media_dir}")
                return jsonify({"error": "Media directory configuration error"}), 500

            for file in os.listdir(media_dir):
                # Check for hidden files (starting with '.') - skip them
                if file.startswith('.'):
                    continue
                if file.lower().endswith('.ts'):
                    try:
                        file_path = os.path.join(media_dir, file)
                        # Ensure it's a file, not a directory or broken link
                        if os.path.isfile(file_path):
                            file_info = {
                                'name': file,
                                'size': os.path.getsize(file_path)
                                # Add 'last_modified': os.path.getmtime(file_path) if needed
                            }
                            media_files.append(file_info)
                    except Exception as file_e:
                         logger.warning(f"Could not get info for file '{file}': {file_e}")
            media_files.sort(key=lambda x: x['name']) # Sort alphabetically
        except Exception as e:
            logger.error(f"Failed to list media in '{media_dir}': {str(e)}")
            return jsonify({"error": "Failed to list media files"}), 500
        return jsonify(media_files)

    @app_instance.route("/media_info/<path:filename>")
    def media_info(filename):
        """ Displays detailed media information (using ffprobe/mediainfo) for a specific file. """
        # Basic security checks for filename safety
        if '..' in filename or filename.startswith('/') or not filename.lower().endswith('.ts'):
             flash("Invalid or disallowed filename.", 'danger')
             return redirect(url_for('index'))

        try:
            media_dir = os.path.abspath(app_instance.stream_manager.media_folder)
            # Securely join path and resolve any symbolic links, etc.
            file_path = os.path.abspath(os.path.join(media_dir, filename))
            # Security check: Ensure the final absolute path is still within the media directory
            if not file_path.startswith(media_dir + os.sep) and file_path != media_dir:
                 raise ValueError("Attempted path traversal.")
            if not os.path.isfile(file_path):
                raise FileNotFoundError("Media file not found.")
        except (FileNotFoundError, ValueError) as e:
            logger.warning(f"Media info access denied or file not found: {filename} ({e})")
            flash(f"Media file '{filename}' not found or access denied.", 'danger')
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Error resolving media file path '{filename}': {e}")
            flash(f"An unexpected error occurred accessing file '{filename}'.", 'danger')
            return redirect(url_for('index'))

        info = app_instance.stream_manager.get_file_info(file_path)
        # Pass an empty form instance needed by base template/CSRF
        # Using StreamForm as a generic placeholder form instance
        dummy_form = StreamForm()
        return render_template('media_info.html', filename=filename, info=info, form=dummy_form)

    @app_instance.route("/stream/<stream_key>")
    def stream_details(stream_key):
        """ Displays the detailed statistics page for a specific active stream. """
        try:
            # Validate key format (should be integer port)
            key = int(stream_key)
            if not (0 < key < 65536):
                 raise ValueError("Port number out of range")
        except (ValueError, TypeError):
            flash("Invalid stream identifier format.", 'danger')
            return redirect(url_for('index'))

        # Retrieve stream details from StreamManager
        # Use .get(key) which returns None if key doesn't exist
        stream_data = app_instance.stream_manager.get_active_streams().get(key)

        if not stream_data:
            flash(f"Stream ({key}) not found or has stopped.", 'warning')
            return redirect(url_for('index'))

        # Pass a dummy form object for CSRF token generation if needed by base templates
        # Even though this page doesn't submit forms, base templates might require it.
        # Use either form type, it just needs to be a FlaskForm instance.
        form = StreamForm() # Using StreamForm as the placeholder instance

        # Pass stream data and the form to the template
        # stream_data contains the 'config' dict which includes 'qos'
        return render_template('stream_details.html',
                               stream_key=key,
                               stream=stream_data,
                               form=form) # Pass the form object

    # --- API Endpoints ---

    @app_instance.route("/get_active_streams")
    def get_active_streams():
        """ API endpoint to get a list of currently active streams and their config. """
        try:
            streams = app_instance.stream_manager.get_active_streams()
            # Consider sanitizing further if sensitive info is in config
            return jsonify(streams)
        except Exception as e:
            logger.error(f"Error getting active streams via API: {e}", exc_info=True)
            return jsonify({"error": "Could not retrieve stream list"}), 500

    @app_instance.route("/api/stats/<stream_key>")
    def get_stats(stream_key):
        """ API endpoint to get detailed statistics for a specific stream. """
        try:
            # Validate key format (should be integer port)
            key = int(stream_key)
            if not (0 < key < 65536):
                 raise ValueError("Port number out of range")
        except (ValueError, TypeError):
             return jsonify({'error': f'Invalid stream key format: {stream_key}'}), 400

        stats = app_instance.stream_manager.get_stream_statistics(stream_key)
        if stats:
            # Ensure stats are JSON serializable (StreamManager should handle this)
            return jsonify(stats)
        else:
            # If stats is None (stream not found or error during fetch in manager)
            return jsonify({'error': f'Stream ({stream_key}) not found or error getting stats'}), 404

    @app_instance.route('/network_test')
    def network_test_page():
        """ Renders the network test configuration page. """
        form = NetworkTestForm()
        system_info = get_system_info() # For context if needed
        return render_template('network_test.html',
                               system_info=system_info,
                               form=form) # Pass the form

    @app_instance.route('/api/network_test', methods=['POST'])
    def network_test_api():
        """ API endpoint to run a network test (iperf3). """
        form = NetworkTestForm() # Use the form for validation
        if form.validate_on_submit():
            try:
                if not network_tester:
                    raise RuntimeError("NetworkTester is not initialized.")

                target = form.target.data or None # Use None if field is empty
                duration = form.duration.data
                bitrate = form.bitrate.data

                logger.info(f"Network test requested via API: target={target}, duration={duration}, bitrate={bitrate}")
                result = network_tester.run_network_test(target, duration, bitrate)
                logger.info(f"Network test completed: server={result.get('server')}, rtt={result.get('rtt_ms')}ms, status={result.get('status')}")
                return jsonify(result)

            except Exception as e:
                logger.error(f"Network test API error: {str(e)}", exc_info=True)
                return jsonify({"error": f"Test execution failed: {str(e)}", "status": "failed"}), 500
        else:
            # Validation failed
            logger.warning(f"Network test form validation failed: {form.errors}")
            # Try to extract a meaningful error message
            first_error_key = next(iter(form.errors), None)
            first_error_msg = form.errors[first_error_key][0] if first_error_key else "Invalid input."
            # Specifically check for CSRF
            csrf_error = form.errors.get('csrf_token')
            error_detail = csrf_error[0] if csrf_error else first_error_msg

            return jsonify({"error": "Validation failed", "details": error_detail, "status": "failed"}), 400

    @app_instance.route('/api/debug/<stream_key>')
    def get_debug_info(stream_key):
        """ API endpoint to get raw debug info for a stream. """
        try:
            # Validate key format (should be integer port)
            key = int(stream_key)
            if not (0 < key < 65536):
                 raise ValueError("Port number out of range")
        except (ValueError, TypeError):
             return jsonify({'error': f'Invalid stream key format: {stream_key}'}), 400

        debug_info = app_instance.stream_manager.get_debug_info(stream_key)
        if debug_info is None: # Should ideally not happen if get_debug_info handles errors internally
             return jsonify({'error': f'Error fetching debug info for stream ({stream_key})'}), 500

        # Check if the returned dict itself contains an error key (e.g., stream not found)
        if 'error' in debug_info:
             # Use 404 if the error indicates 'not found'
             status_code = 404 if 'not found' in debug_info['error'].lower() else 500
             return jsonify(debug_info), status_code

        # Return the full debug info, assuming it's JSON serializable
        try:
            # Attempt to jsonify to catch potential serialization errors early
            response = jsonify(debug_info)
            return response
        except TypeError as e:
            logger.error(f"Failed to serialize debug info for stream {stream_key}: {e}")
            return jsonify({"error": f"Could not serialize debug information for stream {stream_key}"}), 500

    @app_instance.route("/system_info")
    def system_info():
        """ API endpoint to get current system resource usage and time. """
        try:
            info = get_system_info()
            return jsonify(info)
        except Exception as e:
            logger.error(f"Error getting system info via API: {e}", exc_info=True)
            return jsonify({"error": "Could not retrieve system info"}), 500

    @app_instance.route('/health')
    def health_check():
        """ Basic health check endpoint for monitoring. """
        # Could potentially add checks here, e.g., GStreamer availability
        return "OK", 200

    # Register other blueprints or routes here if needed in the future
