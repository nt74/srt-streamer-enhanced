# SRT Streamer Enhanced

## Description

`srt-streamer-enhanced` is a professional solution for testing SRT (Secure Reliable Transport) listeners and callers. Built with Python, Flask, and the GStreamer multimedia framework, it provides a web interface to manage and monitor multiple SRT streams originating from pre-recorded Transport Stream (TS) files.

The core functionality revolves around a carefully configured GStreamer pipeline (`filesrc ! tsparse ! srtsink`) designed for stable, DVB-compliant TS-over-SRT streaming, making it ideal for testing professional SRT IRDs and receivers (Ateme, Appear, Haivision, etc.). The web interface uses Bootstrap 5, jQuery, and Chart.js for a dynamic and informative user experience. Configuration recommendations derived from the Network Test feature are based on principles outlined in documents like the Haivision SRT Deployment Guide.

## Features

* **Multi-Stream Hosting:** Host up to 10 simultaneous SRT streams.
* **Listener & Caller Modes:** Easily start streams in either Listener (server) or Caller (client) mode via dedicated forms.
* **GStreamer Pipeline (`filesrc ! tsparse ! srtsink`):**
    * Reads local `.ts` files using `filesrc`.
    * Parses Transport Streams using `tsparse` with timestamping, 7-packet alignment, and **`smoothing-latency=20000` (20ms)** to reduce PCR jitter for professional receivers.
    * Transmits using `srtsink` configured with user-defined latency, overhead, encryption, and specific DVB/SRT parameters (large buffers, `tlpktdrop`, NAK reports, etc.).
* **DVB Compliance Focus:** Applies specific SRT parameters (`dvb_config.py`) and `tsparse` settings suitable for DVB transport stream carriage.
* **Integrated Network Testing:** Measures RTT/Loss using `ping`/`iperf3`, recommends SRT Latency/Overhead (based on SRT Guide principles), and allows applying settings to the stream form.
* **Real-time Monitoring & Statistics:** Dashboard with live status, detailed stream view with charts (Chart.js) for Bitrate/RTT/Loss history, packet counters, buffer levels, and debug info API.
* **Media Management:** AJAX media browser modal lists `.ts` files; Media Info page uses `ffprobe`/`mediainfo`. Potential upload support.
* **Dynamic Web Interface:** Built with Bootstrap 5, jQuery. Includes dashboard, caller page, network test page, stream details. AJAX updates for system info & streams. Theme switcher.
* **Secure Access & Operations:** NGINX Basic Auth frontend; Flask-WTF CSRF Protection; requires strong `SECRET_KEY`.
* **Health Check:** Endpoint at `/health`.
* **Potential Feature (TS Analyzer):** Code exists (`ts_analyzer.py`) for deeper DVB TS analysis but is not currently integrated into the UI.

## Technology Stack

* **Backend:** Python 3, Flask, Flask-WTF, Waitress, GStreamer 1.0 (via PyGObject), `requests`, `psutil`.
* **Frontend:** Bootstrap 5, jQuery, Chart.js, Font Awesome (via CDN), Jinja2, Custom JS.
* **Supporting:** NGINX, `ffmpeg` (ffprobe), `mediainfo`, `iperf3`, `ping`, `curl`, `dig`, Systemd (recommended).

## Architecture Overview

1.  **Backend (`app/`):** Python/Flask app. `StreamManager` controls GStreamer. `NetworkTester` runs checks. `utils.py` provides system info. Logs to `/var/log/srt-streamer/srt_streamer.log`. Caches in `app/data/`.
2.  **Frontend (NGINX):** Reverse proxy, Basic Auth, serves static files.
3.  **Startup (`start.sh`):** Tunes network, fetches IP, activates venv, starts Waitress.
4.  **GStreamer Pipeline Structure:** The core streaming logic uses a GStreamer pipeline dynamically constructed similar to this template:
    ```gst-pipeline
    filesrc location="..." ! \
    tsparse name="tsparse_..." set-timestamps=true alignment=7 smoothing-latency=20000 parse-private-sections=true ! \
    srtsink name="srtsink_..." uri="srt://..." [SRT params like mode, latency, overhead, encryption, DVB settings] wait-for-connection=true
    ```
    The `smoothing-latency=20000` (20ms) on `tsparse` is specifically chosen to improve PCR timing stability for professional broadcast equipment.

## System Requirements

* **Operating System:** Debian/Ubuntu or Rocky Linux/RHEL (or equivalent distributions with GStreamer 1.0+ support).
* **RAM:** Allocate approximately 1 GB of RAM per simultaneous SRT stream planned. For the maximum of 10 streams, at least 10 GB of RAM is recommended.
* **CPU/GPU:** CPU usage is expected to be relatively low as the application primarily shuffles TS packets between file input and the SRT protocol (demuxing/remuxing) rather than performing computationally intensive transcoding or encoding. GPU is not utilized.
* **Network:** A stable network connection with sufficient bandwidth (considering stream bitrate + SRT overhead) is required. Network tuning (via `start.sh` or system configuration) is recommended for optimal performance, especially for high-bitrate streams.

## Target Environments

Linux distributions with GStreamer 1.0 support: Ubuntu/Debian, Rocky/RHEL/Fedora families.

## Installation Guide

*(Assumes default installation path `/opt/srt-streamer-enhanced` and venv path `/opt/venv`. Adapt if necessary.)*

1.  **Get the Code:**
    * Clone the repository or download the source code.
        ```bash
        # Example using git
        sudo git clone <repository_url> /opt/srt-streamer-enhanced
        cd /opt/srt-streamer-enhanced
        ```

2.  **Install System Dependencies:**
    * Install necessary packages for your distribution.
    * **Debian / Ubuntu:**
        ```bash
        sudo apt update && sudo apt install -y \
            python3 python3-pip python3-venv python3-gi gir1.2-gobject-2.0 \
            gir1.2-gst-rtsp-server-1.0 gir1.2-glib-2.0 libgirepository1.0-dev \
            gcc libcairo2-dev pkg-config python3-dev \
            gir1.2-gstreamer-1.0 gir1.2-gst-plugins-base-1.0 \
            gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
            gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
            gstreamer1.0-tools gstreamer1.0-libav \
            nginx curl iperf3 iputils-ping dnsutils ffmpeg mediainfo
        ```
    * **RHEL / Rocky / Fedora:**
        ```bash
        sudo dnf update && sudo dnf install -y \
            python3 python3-pip python3-gobject gobject-introspection-devel \
            cairo-gobject-devel python3-devel pkgconf-pkg-config gcc \
            gstreamer1 gstreamer1-plugins-base gstreamer1-plugins-good \
            gstreamer1-plugins-bad-free gstreamer1-plugins-ugly-free gstreamer1-libav \
            nginx curl iperf3 iputils bind-utils ffmpeg mediainfo
        ```
        *(Use `yum` instead of `dnf` on older RHEL/CentOS)*

3.  **Set Up Python Environment:**
    * Create a virtual environment:
        ```bash
        sudo python3 -m venv /opt/venv
        ```
    * Activate the virtual environment:
        ```bash
        source /opt/venv/bin/activate
        ```
    * Install required Python packages using the provided `requirements.txt`:
        ```bash
        pip install -r requirements.txt
        ```
    * Deactivate the environment (it will be activated by `start.sh` or the systemd service):
        ```bash
        deactivate
        ```

4.  **Configure Application:**
    * **Media Files:** Place your `.ts` source files into `/opt/srt-streamer-enhanced/media/`.
    * **Log/Data Directories:** Create directories and set permissions (adjust owner if not running service as root):
        ```bash
        sudo mkdir -p /var/log/srt-streamer /opt/srt-streamer-enhanced/app/data
        sudo chown root:root /var/log/srt-streamer /opt/srt-streamer-enhanced/app/data
        ```
    * **NGINX:**
        * Configure Nginx as a reverse proxy for `http://127.0.0.1:5000`. A sample config snippet might look like:
          ```nginx
          server {
              listen 80; # Or your desired port
              server_name your_server_ip_or_domain;

              location / {
                  proxy_pass [http://127.0.0.1:5000](http://127.0.0.1:5000);
                  proxy_set_header Host $host;
                  proxy_set_header X-Real-IP $remote_addr;
                  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                  proxy_set_header X-Forwarded-Proto $scheme;

                  # Basic Authentication
                  auth_basic "Restricted Content";
                  auth_basic_user_file /etc/nginx/.htpasswd; # Path to your password file
              }
          }
          ```
        * Create a password file for Basic Authentication (e.g., for user `admin`):
          ```bash
          sudo apt install -y apache2-utils # Debian/Ubuntu
          # sudo dnf install -y httpd-tools # RHEL/Fedora
          sudo htpasswd -c /etc/nginx/.htpasswd admin
          # Enter a strong password when prompted
          sudo chown www-data:www-data /etc/nginx/.htpasswd # Adjust owner for your Nginx user
          sudo chmod 640 /etc/nginx/.htpasswd
          ```
        * Enable the Nginx site and test configuration:
          ```bash
          # Example: sudo ln -s /etc/nginx/sites-available/srt-streamer /etc/nginx/sites-enabled/
          sudo nginx -t
          sudo systemctl restart nginx
          ```
    * **Flask Secret Key:** Generate a strong secret key:
        ```bash
        openssl rand -hex 32
        ```
        **Copy this key.** You will need it for the systemd service file or to set it as an environment variable manually. **DO NOT use a default or weak key.**
    * **Startup Script:** Make `start.sh` executable:
        ```bash
        sudo chmod +x /opt/srt-streamer-enhanced/start.sh
        ```

5.  **Set Up Systemd Service (Recommended):**
    * Create the service file `/etc/systemd/system/srt-streamer.service`:
        ```ini
        [Unit]
        Description=SRT Streamer Enhanced - DVB Compliant
        After=network.target nginx.service # Ensure Nginx starts first

        [Service]
        Type=simple
        User=root # Simplifies permissions, review if non-root needed
        WorkingDirectory=/opt/srt-streamer-enhanced

        # --- IMPORTANT: Paste your generated SECRET_KEY here! ---
        Environment="SECRET_KEY=paste_your_generated_secret_key_here"
        # Optional: Override media folder
        # Environment="MEDIA_FOLDER=/srv/media/srt-sources"

        ExecStart=/opt/srt-streamer-enhanced/start.sh
        Restart=on-failure
        RestartSec=5
        StandardOutput=journal
        StandardError=journal

        [Install]
        WantedBy=multi-user.target
        ```
    * **Paste your generated `SECRET_KEY`** into the `Environment=` line.
    * Reload systemd, enable and start the service:
        ```bash
        sudo systemctl daemon-reload
        sudo systemctl enable srt-streamer.service
        sudo systemctl start srt-streamer.service
        ```

6.  **Verify:**
    * Check the service status: `sudo systemctl status srt-streamer.service`
    * Check logs: `sudo journalctl -u srt-streamer.service -f` and `sudo tail -f /var/log/srt-streamer/srt_streamer.log`.
    * Access the application via the Nginx URL in your browser and log in with the `admin` user and the password you set.

## Usage Workflow

1.  **Access & Login:** Open the application URL, log in via NGINX Basic Auth.
2.  **Dashboard (`/`):** View system status, active streams. Use form to start Listener streams (use `Browse` modal for file selection).
3.  **Start Caller (`/caller`):** Navigate here to start Caller streams (specify target, select file via `Browse` modal).
4.  **Network Test (`/network_test`):** Run tests, view results/recommendations. Click "Apply..." to pre-fill Listener form on dashboard.
5.  **View Details (`/stream/<key>`):** Click "View Details" on dashboard. Monitor live stats, charts, status. Access debug info.
6.  **Stop Streams:** Use "Stop" buttons on dashboard or details page.

## Configuration & Tuning Tips (from SRT Guide)

* **SRT Latency:** This determines the buffer size for handling network jitter and packet retransmissions[cite: 290, 376]. It should generally be set to at least RTT Multiplier * RTT[cite: 323]. A common starting point is 4x RTT for decent networks[cite: 381]. The higher value set between the sender and receiver is used[cite: 385].
* **Bandwidth Overhead:** Reserve extra bandwidth (%) for packet retransmissions[cite: 361]. Higher loss rates require more overhead[cite: 349]. Ensure `Stream Bitrate * (1 + Overhead %)` is well within your available channel capacity[cite: 306].
* **Monitoring Buffers (Stream Details Page):**
    * **Sender:** If the "Send Buffer Level" consistently exceeds the configured "Latency" line, your bitrate might be too high for the available bandwidth, or the overhead is insufficient[cite: 617, 472]. Consider lowering bitrate first. If it only spikes occasionally, increasing Latency might help[cite: 473].
    * **Receiver:** If the "Recv Buffer Level" often drops near zero, it indicates packets aren't arriving in time[cite: 470]. If this happens frequently, the bitrate may be too high[cite: 470]. If occasional, increasing Latency might provide more time for recovery[cite: 471].
* **Packet Loss:** "Lost Packets" reported by the sender indicate network drops[cite: 424]. "Skipped Packets" reported by the receiver mean packets arrived too late (or never) to be played, potentially causing artifacts[cite: 427, 630]. If skipped packets increase slowly, try increasing Latency[cite: 638]; if in large jumps, try lowering bitrate or increasing Bandwidth Overhead[cite: 639].

## References

* Haivision, "SRT Protocol Deployment Guide Version 1.5.x", 28 Mar 2025. [cite: 1] (Provided PDF)
* SRT Alliance: [https://www.srtalliance.org/](https://www.srtalliance.org/)
* SRT GitHub Repository: [https://github.com/Haivision/srt](https://github.com/Haivision/srt)

---
