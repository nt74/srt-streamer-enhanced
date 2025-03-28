# Full content for app/routes.py (Corrected AGAIN - Focus on stream_details)

from flask import (
    render_template, request, jsonify, send_from_directory, 
    redirect, url_for, flash, current_app as app 
)
# Import ALL needed forms from app.forms
from app.forms import (
    StreamForm, CallerForm, NetworkTestForm, MediaUploadForm 
    # Add SettingsForm if you implement a settings page later
) 
from app.utils import get_system_info
from app.network_test import NetworkTester # Assuming NetworkTester is correctly implemented
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Initialize network tester 
try:
    network_tester = NetworkTester()
except Exception as e:
     logger.error(f"Failed to initialize NetworkTester: {e}")
     network_tester = None 

# Wrap route definitions in a function called by __init__
def register_routes(app_instance):

    @app_instance.route('/')
    def index():
        form = StreamForm()
        error_message = request.args.get('error') 
        
        if request.args.get('apply_network_test'):
            try:
                latency_arg = request.args.get('latency')
                overhead_arg = request.args.get('overhead')
                applied_settings = False
                if latency_arg is not None:
                    form.latency.data = int(latency_arg)
                    applied_settings = True
                if overhead_arg is not None:
                    form.overhead_bandwidth.data = int(overhead_arg)
                    applied_settings = True
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
        form = StreamForm()
        system_info = get_system_info() 
        active_streams = app_instance.stream_manager.get_active_streams()

        if form.validate_on_submit():
            if form.mode.data and form.mode.data != 'listener':
                 flash('Incorrect form submission for listener mode.', 'danger')
                 return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=None)

            try:
                 file_to_check = form.file_path.data
                 if not file_to_check: raise ValueError("File path is empty.")
                 file_path = os.path.join(app_instance.stream_manager.media_folder, file_to_check)
                 if not os.path.isfile(file_path): raise FileNotFoundError(f"File not found: {file_path}")
            except Exception as e:
                 flash(f"Invalid media file selected: {e}", 'danger')
                 return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=None)

            config = { 'port': form.port.data, 'latency': form.latency.data, 'overhead_bandwidth': form.overhead_bandwidth.data, 'mode': 'listener', 'encryption': form.encryption.data, 'passphrase': form.passphrase.data, 'target_address': None, 'dvb_compliant': True }
            logger.info(f"Attempting to start LISTENER stream with config: {config}")
            success, message = app_instance.stream_manager.start_stream(file_path, config) 
            
            if success:
                logger.info(f"Listener stream start initiated: {message}")
                flash(f"Listener stream started successfully on port {config.get('port', 'N/A')}.", 'success')
                return redirect(url_for('index'))
            else:
                logger.error(f"Listener stream start failed: {message}")
                flash(f"Failed to start listener stream: {message}", 'danger')
                return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=message)
        else:
            flash('Please correct the errors in the listener configuration form.', 'warning')
            return render_template('index.html', form=form, system_info=system_info, active_streams=active_streams, error=None)

    @app_instance.route('/caller', methods=['GET', 'POST'])
    def caller_page():
        form = CallerForm()
        error_message = None 

        if form.validate_on_submit():
            try:
                 file_to_check = form.file_path.data
                 if not file_to_check: raise ValueError("File path is empty.")
                 file_path = os.path.join(app_instance.stream_manager.media_folder, file_to_check)
                 if not os.path.isfile(file_path): raise FileNotFoundError(f"File not found: {file_path}")
            except Exception as e:
                 flash(f"Invalid media file selected: {e}", 'danger')
                 return render_template('caller.html', form=form, error=None) 

            config = { 'mode': 'caller', 'target_address': form.target_address.data, 'target_port': form.target_port.data, 'latency': form.latency.data, 'overhead_bandwidth': form.overhead_bandwidth.data, 'encryption': form.encryption.data, 'passphrase': form.passphrase.data, 'dvb_compliant': True }
            logger.info(f"Attempting to start CALLER stream with config: {config}")
            success, message = app_instance.stream_manager.start_stream(file_path, config, use_target_port_as_key=True)

            if success:
                logger.info(f"Caller stream start initiated: {message}")
                flash(f"Caller stream to {config.get('target_address', 'N/A')}:{config.get('target_port', 'N/A')} started.", 'success')
                return redirect(url_for('index')) 
            else:
                logger.error(f"Caller stream start failed: {message}")
                error_message = f"Failed to start caller stream: {message}"
                return render_template('caller.html', form=form, error=error_message)
                
        return render_template('caller.html', form=form, error=error_message)

    @app_instance.route("/stop_stream/<stream_key>", methods=["POST"])
    def stop_stream(stream_key):
         if not stream_key or not stream_key.isdigit() or not (0 < int(stream_key) < 65536):
              flash("Invalid stream identifier provided.", 'danger')
              return redirect(url_for('index'))
              
         success, message = app_instance.stream_manager.stop_stream(stream_key) 
         if success:
             logger.info(f"Stream stopped: {message}")
             flash(f"Stream ({stream_key}) stopped successfully.", 'success')
         else:
             logger.error(f"Stream stop failed: {message}")
             flash(f"Failed to stop stream ({stream_key}): {message}", 'danger')
         return redirect(url_for('index'))

    @app_instance.route("/media")
    def list_media():
        media_files = []
        media_dir = app_instance.stream_manager.media_folder
        try:
            if not os.path.isdir(media_dir):
                 logger.error(f"Media directory not found: {media_dir}")
                 return jsonify({"error": "Media directory configuration error"}), 500
                 
            for file in os.listdir(media_dir):
                if file.lower().endswith('.ts'):
                    try:
                        file_path = os.path.join(media_dir, file)
                        if os.path.isfile(file_path):
                             file_info = {'name': file, 'size': os.path.getsize(file_path)}
                             media_files.append(file_info)
                    except Exception as file_e:
                         logger.warning(f"Could not get info for file '{file}': {file_e}")
            media_files.sort(key=lambda x: x['name'])
        except Exception as e:
            logger.error(f"Failed to list media in '{media_dir}': {str(e)}")
            return jsonify({"error": "Failed to list media files"}), 500
        return jsonify(media_files)

    @app_instance.route("/media_info/<path:filename>")
    def media_info(filename):
        if '..' in filename or filename.startswith('/') or not filename.lower().endswith('.ts'):
             flash("Invalid or disallowed filename.", 'danger')
             return redirect(url_for('index'))
             
        try:
             media_dir = os.path.abspath(app_instance.stream_manager.media_folder)
             file_path = os.path.abspath(os.path.join(media_dir, filename))
             if not file_path.startswith(media_dir + os.sep) and file_path != media_dir:
                  raise ValueError("Attempted path traversal.")
             if not os.path.isfile(file_path): raise FileNotFoundError()
        except (FileNotFoundError, ValueError) as e:
             logger.warning(f"Media info access denied or file not found: {filename} ({e})")
             flash(f"Media file '{filename}' not found or access denied.", 'danger')
             return redirect(url_for('index')) 
             
        info = app_instance.stream_manager.get_file_info(file_path)
        return render_template('media_info.html', filename=filename, info=info)

    # --- Re-corrected stream_details route ---
    @app_instance.route("/stream/<stream_key>")
    def stream_details(stream_key):
        try:
             key = int(stream_key)
        except (ValueError, TypeError):
             flash("Invalid stream identifier format.", 'danger')
             return redirect(url_for('index'))
             
        stream = app_instance.stream_manager.get_active_streams().get(key)
        if not stream:
            flash(f"Stream ({key}) not found or has stopped.", 'warning')
            return redirect(url_for('index'))
            
        # ***** THIS IS THE CRITICAL FIX *****
        # Instantiate a form object to pass to the template
        form = StreamForm() # Or CallerForm(), any WTForm instance works
        
        # Pass 'form=form' to render_template
        return render_template('stream_details.html', 
                               stream_key=key, 
                               stream=stream, 
                               form=form) 
        # ***** END FIX *****

    @app_instance.route("/get_active_streams")
    def get_active_streams():
        try:
             streams = app_instance.stream_manager.get_active_streams()
             return jsonify(streams)
        except Exception as e:
             logger.error(f"Error getting active streams via API: {e}", exc_info=True)
             return jsonify({"error": "Could not retrieve stream list"}), 500
        
    @app_instance.route("/api/stats/<stream_key>")
    def get_stats(stream_key):
         if not stream_key or not stream_key.isdigit():
              return jsonify({'error': f'Invalid stream key format: {stream_key}'}), 400
              
         stats = app_instance.stream_manager.get_stream_statistics(stream_key)
         if stats:
             return jsonify(stats)
         return jsonify({'error': f'Stream ({stream_key}) not found or error getting stats'}), 404 

    # --- Corrected network_test_page route ---
    @app_instance.route('/network_test')
    def network_test_page():
        form = NetworkTestForm() 
        system_info = get_system_info()
        return render_template('network_test.html', 
                            system_info=system_info, 
                            form=form) # Pass form

    # --- Corrected network_test_api route ---
    @app_instance.route('/api/network_test', methods=['POST']) 
    def network_test_api():
        form = NetworkTestForm() 
        if form.validate_on_submit(): 
            try:
                if not network_tester:
                     raise RuntimeError("NetworkTester is not initialized.")
                     
                target = form.target.data or None 
                duration = form.duration.data
                bitrate = form.bitrate.data
                
                logger.info(f"Network test requested: target={target}, duration={duration}, bitrate={bitrate}")
                result = network_tester.run_network_test(target, duration, bitrate)
                logger.info(f"Network test completed: server={result.get('server')}, rtt={result.get('rtt_ms')}ms")
                return jsonify(result)
                
            except Exception as e:
                logger.error(f"Network test API error: {str(e)}", exc_info=True) 
                return jsonify({"error": f"Test execution failed: {str(e)}", "status": "failed"}), 500
        else:
             logger.warning(f"Network test form validation failed: {form.errors}")
             csrf_error = form.errors.get('csrf_token')
             error_detail = csrf_error[0] if csrf_error else "Invalid form data. Check inputs."
             return jsonify({"error": "Validation failed", "details": error_detail}), 400 

    @app_instance.route('/api/debug/<stream_key>')
    def get_debug_info(stream_key):
         if not stream_key or not stream_key.isdigit():
              return jsonify({'error': f'Invalid stream key format: {stream_key}'}), 400
              
         debug_info = app_instance.stream_manager.get_debug_info(stream_key)
         if debug_info is None: 
              return jsonify({'error': f'Error fetching debug info for stream ({stream_key})'}), 500
         if 'error' in debug_info: 
              return jsonify(debug_info), 404 
         return jsonify(debug_info)

    @app_instance.route("/system_info")
    def system_info():
        try:
            info = get_system_info()
            return jsonify(info)
        except Exception as e:
             logger.error(f"Error getting system info via API: {e}", exc_info=True)
             return jsonify({"error": "Could not retrieve system info"}), 500
