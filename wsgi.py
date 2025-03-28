from app import app
from waitress import serve
import os
import logging

if __name__ == "__main__":
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))
    threads = int(os.environ.get('THREADS', 4))
    
    logging.info(f"Starting SRT Streamer Enhanced on {host}:{port} with {threads} threads")
    serve(app, host=host, port=port, threads=threads)
