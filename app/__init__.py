# Full content for app/__init__.py (Explicit CSRF)

from flask import Flask
import os
import logging
from logging.handlers import RotatingFileHandler
from app.stream_manager import StreamManager
# Import CSRFProtect
from flask_wtf.csrf import CSRFProtect 

# Configure logging
log_dir_standard = '/var/log/srt-streamer' 
logging.basicConfig(level=logging.INFO) 
logger = logging.getLogger() 

# --- File Handler using standard path ---
try:
    if not os.path.exists(log_dir_standard):
         try:
             os.makedirs(log_dir_standard, mode=0o755) 
             logger.info(f"Created log directory: {log_dir_standard}")
         except Exception as dir_e:
             logger.error(f"Failed to create log directory {log_dir_standard}: {dir_e}. Logging to file might fail.")

    log_file_path = os.path.join(log_dir_standard, 'srt_streamer.log')
    
    file_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO) 
    logger.addHandler(file_handler)
    logger.info(f"Logging to file: {log_file_path}")

except Exception as log_e:
     logger.error(f"Failed to set up file logging to {log_dir_standard}: {log_e}")
     logger.warning("File logging setup failed. Check directory permissions.")

# --- Initialize Flask App ---
app = Flask(__name__)
# ** IMPORTANT: Ensure SECRET_KEY is set via environment variable **
# Example: export SECRET_KEY='your_random_strong_secret'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-strong-dev-secret-key-please-change') 
if app.config['SECRET_KEY'] == 'a-very-strong-dev-secret-key-please-change':
     logger.warning("SECURITY WARNING: Using default SECRET_KEY. Set the SECRET_KEY environment variable.")
     
app.config['MEDIA_FOLDER'] = os.environ.get('MEDIA_FOLDER', '/opt/srt-streamer-enhanced/media')

# --- Explicitly Initialize CSRF Protection ---
csrf = CSRFProtect(app) 
logger.info("CSRF protection initialized.")

# Initialize managers
app.stream_manager = StreamManager(app.config['MEDIA_FOLDER'])

# Register routes 
from app.routes import register_routes
register_routes(app) 

app.logger.info('SRT Streamer Enhanced Application initialized')

# Health check endpoint
@app.route('/health')
def health_check():
     return "OK", 200
