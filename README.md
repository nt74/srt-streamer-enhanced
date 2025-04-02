# SRT Streamer Enhanced

## Description

`srt-streamer-enhanced` is a professional solution for testing SRT (Secure Reliable Transport) listeners and callers. Built with Python, Flask, and the GStreamer multimedia framework, it provides a web interface to manage and monitor multiple SRT streams originating from pre-recorded Transport Stream (TS) files.

The core functionality revolves around a carefully configured GStreamer pipeline (`filesrc ! tsparse ! srtsink`) designed for stable, DVB-compliant TS-over-SRT streaming, making it ideal for testing professional SRT IRDs and receivers (Ateme, Appear, Haivision, etc.). It includes an advanced network testing tool using `ping` and `iperf3` (**TCP for automatic tests, selectable TCP/UDP for manual tests**) to provide SRT configuration recommendations (Latency, Overhead) based on principles outlined in the Haivision SRT Deployment Guide. *** UPDATED Network Test Description *** The web interface uses Bootstrap 5, jQuery, and Chart.js for a dynamic and informative user experience.

## Features

* **Multi-Stream Hosting:** Host up to 10 simultaneous SRT streams.
* **Listener & Caller Modes:** Easily start streams in either Listener (server) or Caller (client) mode via dedicated web UI forms.
* **GStreamer Pipeline (`filesrc ! tsparse ! srtsink`):**
    * Reads local `.ts` files using `filesrc`.
    * Parses Transport Streams using `tsparse` with timestamping, 7-packet alignment, and **`smoothing-latency=20000` (20ms)** to reduce PCR jitter for professional receivers.
    * Transmits using `srtsink` configured with user-defined latency, overhead, encryption, Quality of Service (QoS) flag, and specific DVB/SRT parameters (large buffers, `tlpktdrop`, NAK reports, etc.). *** CHANGED ***
* **DVB Compliance Focus:** Applies specific SRT parameters (`dvb_config.py`) and `tsparse` settings suitable for DVB transport stream carriage.
* **Configurable Stream Parameters (UI):** Set Latency (20-8000ms), Overhead (1-99%), Encryption (None, AES-128, AES-256 with passphrase), and QoS flag. *** UPDATED Overhead Range ***
* **Configurable QoS:** Option via UI to enable/disable the SRT Quality of Service flag (`qos=true|false`) in the outgoing SRT URI. *** ADDED ***
* **Accurate Stats Parsing:** Correctly parses detailed SRT statistics strings from `srtsink` for both Listener and Caller modes. *** ADDED ***
* **Integrated Network Testing:** *** UPDATED Network Test Logic ***
    * Measures RTT using `ping`.
    * Measures Bandwidth using `iperf3` (**TCP for Auto modes, selectable TCP/UDP for Manual mode**). Loss/Jitter metrics are primarily available from UDP tests.
    * **Multiple Modes:** Offers "Auto (Closest)" (TCP iperf3 based on GeoIP location), "Auto (Regional)" (TCP iperf3 testing random servers in a chosen continent), and "Manual" mode (selectable TCP or UDP iperf3).
    * **Haivision-Based Recommendations:** Recommends SRT Latency/Overhead based on measured RTT and Loss (Note: Loss is assumed when using TCP tests, typically resulting in higher recommendations), derived from Haivision SRT Deployment Guide principles.
    * **Apply Settings:** Allows applying recommended settings directly to the Listener stream form.
* **Real-time Monitoring & Statistics:** Dashboard with live status, detailed stream view with charts (Chart.js) for Bitrate/RTT/Loss history, packet counters, buffer levels, connection status (including inferred caller IP for listeners), and debug info API. *** CHANGED ***
* **Media Management:** AJAX media browser modal lists `.ts` files; Media Info page uses `ffprobe`/`mediainfo`.
* **Dynamic Web Interface:** Built with Bootstrap 5, jQuery. Includes dashboard, caller page, network test page, stream details. AJAX updates for system info & streams. Theme switcher.
* **Secure Access & Operations:** NGINX Basic Auth frontend; Flask-WTF CSRF Protection; requires strong `SECRET_KEY`.
* **Health Check:** Endpoint at `/health`.
* **Potential Feature (TS Analyzer):** Code exists (`ts_analyzer.py`) for deeper DVB TS analysis but is not currently integrated into the UI.

## Technology Stack

* **Backend:** Python 3, Flask, Flask-WTF, Waitress, GStreamer 1.0 (via PyGObject), `requests`, `psutil`.
* **Frontend:** Bootstrap 5, jQuery, Chart.js, Font Awesome (via CDN), Jinja2, Custom JS.
* **Supporting:** NGINX, `ffmpeg` (for ffprobe), `mediainfo`, `iperf3`, `ping` (iputils-ping), `curl`, `dig` (dnsutils/bind-utils), Systemd (recommended).

## Architecture Overview

1.  **Backend (`app/`):** Python/Flask app. `StreamManager` controls GStreamer. `NetworkTester` runs checks. `utils.py` provides system info. Logs to `/var/log/srt-streamer/srt_streamer.log`. Caches in `app/data/`.
2.  **Frontend (NGINX):** Reverse proxy, Basic Auth, serves static files.
3.  **Service Management (Systemd):** Recommended startup uses two systemd units:
    * `network-tuning.service`: Applies network `sysctl` optimizations at boot (runs `network-tuning.sh`).
    * `srt-streamer.service`: Manages the main application process, activating the Python virtual environment and running the Waitress server via `wsgi.py`. It depends on `network-tuning.service`.
4.  **GStreamer Pipeline Structure:** The core streaming logic uses a GStreamer pipeline dynamically constructed similar to this template:
    ```gst-pipeline
    filesrc location="..." ! \
    tsparse name="tsparse_..." set-timestamps=true alignment=7 smoothing-latency=20000 parse-private-sections=true ! \
    srtsink name="srtsink_..." uri="srt://HOST:PORT?mode=...&latency=...&overheadbandwidth=...&passphrase=...&pbkeylen=...&qos=..." [Other Params: buffer sizes, tlpktdrop, etc.]
    ```
    * *** CHANGED: Updated example URI parameters (`overheadbandwidth`, `qos`) and removed explicit `wait-for-connection`. ***
    * The `smoothing-latency=20000` (20ms) on `tsparse` is specifically chosen to improve PCR timing stability for professional broadcast equipment.

## System Requirements

* **Operating System:** Debian/Ubuntu or Rocky Linux/RHEL (or equivalent distributions with GStreamer 1.0+ support).
* **RAM:** Allocate approximately 1 GB of RAM per simultaneous SRT stream planned. For the maximum of 10 streams, at least 10 GB of RAM is recommended.
* **CPU/GPU:** CPU usage is expected to be relatively low. GPU is not utilized.
* **Network:** Stable network connection with sufficient bandwidth (stream bitrate + SRT overhead). Network tuning (`network-tuning.sh`) recommended.

## Target Environments

Linux distributions with GStreamer 1.0 support: Ubuntu/Debian, Rocky/RHEL/Fedora families.

## Installation Guide

*(Assumes default installation path `/opt/srt-streamer-enhanced` and venv path `/opt/venv`. Adapt if necessary.)*

1.  **Get the Code:**
    * Clone the repository or download the source code.
        ```bash
        # Example using git
        sudo git clone [https://github.com/nt74/srt-streamer-enhanced.git](https://github.com/nt74/srt-streamer-enhanced.git) /opt/srt-streamer-enhanced
        cd /opt/srt-streamer-enhanced
        ```

2.  **Install System Dependencies:** *** MERGED: Added Detailed Commands ***
    * Install necessary packages for your distribution (Python 3, pip, venv, GStreamer + plugins, Nginx, curl, iperf3, ping, dig, ffmpeg, mediainfo, htpasswd).
    * **Debian / Ubuntu Example:**
        ```bash
        sudo apt update && sudo apt install -y \
            python3 python3-pip python3-venv python3-gi gir1.2-gobject-2.0 \
            gir1.2-gst-rtsp-server-1.0 gir1.2-glib-2.0 libgirepository1.0-dev \
            gcc libcairo2-dev pkg-config python3-dev \
            gir1.2-gstreamer-1.0 gir1.2-gst-plugins-base-1.0 \
            gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
            gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
            gstreamer1.0-tools gstreamer1.0-libav \
            nginx curl iperf3 iputils-ping dnsutils ffmpeg mediainfo apache2-utils
        ```
    * **RHEL / Rocky / Fedora Example:**
        ```bash
        sudo dnf update && sudo dnf install -y \
            python3 python3-pip python3-gobject gobject-introspection-devel \
            cairo-gobject-devel python3-devel pkgconf-pkg-config gcc \
            gstreamer1 gstreamer1-plugins-base gstreamer1-plugins-good \
            gstreamer1-plugins-bad-free gstreamer1-plugins-ugly-free gstreamer1-libav \
            nginx curl iperf3 iputils bind-utils ffmpeg mediainfo httpd-tools
        ```
        *(Use `yum` instead of `dnf` on older RHEL/CentOS)*

3.  **Set Up Python Environment:**
    * Create and activate a Python virtual environment (e.g., `/opt/venv`).
        ```bash
        sudo python3 -m venv /opt/venv
        source /opt/venv/bin/activate
        ```
    * Install required Python packages using `requirements.txt`:
        ```bash
        pip install -r requirements.txt
        ```
    * Deactivate the environment.
        ```bash
        deactivate
        ```

4.  **Configure Application:**
    * **Media Files:** Place your `.ts` source files into `/opt/srt-streamer-enhanced/media/`. Create the directory if it doesn't exist.
        ```bash
        sudo mkdir -p /opt/srt-streamer-enhanced/media
        # Add your .ts files here, then set permissions
        sudo chown root:root /opt/srt-streamer-enhanced/media # Adjust owner later if needed
        sudo chmod 755 /opt/srt-streamer-enhanced/media # Ensure directory is accessible
        sudo chown root:root /opt/srt-streamer-enhanced/media/*.ts # Adjust owner later if needed
        sudo chmod 644 /opt/srt-streamer-enhanced/media/*.ts # Ensure files are readable
        ```
    * **Log/Data Directories:** Create directories and set permissions (assuming service runs as root):
        ```bash
        sudo mkdir -p /var/log/srt-streamer /opt/srt-streamer-enhanced/app/data
        sudo chown root:root /var/log/srt-streamer /opt/srt-streamer-enhanced/app/data
        # Adjust owner if you modify the systemd service to run as a different user
        # Ensure external_ip.txt exists and is writable by the process that updates it (if applicable)
        sudo touch /opt/srt-streamer-enhanced/app/data/external_ip.txt
        # Example: sudo chown <your_service_user>:root /opt/srt-streamer-enhanced/app/data/external_ip.txt
        ```
    * **NGINX:**
        * Configure Nginx as a reverse proxy for `http://127.0.0.1:5000`.
        * Create a password file (e.g., `/etc/nginx/.htpasswd`) for Basic Authentication using `htpasswd`. **Set a strong password and change the example user `admin`.** Secure the file permissions.
            ```bash
            sudo htpasswd -c /etc/nginx/.htpasswd admin
            # Enter password
            # Check Nginx user (e.g., www-data on Debian, nginx on RHEL) and set ownership
            # sudo ps aux | grep nginx
            NGINX_USER=$(ps aux | grep '[n]ginx: worker process' | head -n 1 | awk '{print $1}')
            [ -z "$NGINX_USER" ] && NGINX_USER=nginx # Default fallback
            sudo chown $NGINX_USER:$NGINX_USER /etc/nginx/.htpasswd # Adjust group if needed
            sudo chmod 640 /etc/nginx/.htpasswd
            ```
        * Add/Enable the Nginx site configuration and test/restart Nginx.
            ```bash
            # Example: sudo ln -s /opt/srt-streamer-enhanced/nginx.conf /etc/nginx/sites-enabled/srt-streamer
            sudo nginx -t
            sudo systemctl restart nginx
            ```
    * **Flask Secret Key:** Generate a strong secret key:
        ```bash
        openssl rand -hex 32
        ```
        **Copy this key.** You will need it for the systemd service file in the next step.

5.  **Set Up Systemd Services (Recommended):**
    * **Network Tuning Script:** Ensure the network tuning script exists at `/opt/srt-streamer-enhanced/network-tuning.sh` and is executable:
        ```bash
        sudo chmod +x /opt/srt-streamer-enhanced/network-tuning.sh
        ```
    * **Network Tuning Service:** Create the service file `/etc/systemd/system/network-tuning.service`:
        ```ini
        [Unit]
        Description=Apply Network Settings for SRT Streamer Enhanced
        After=network.target
        Before=srt-streamer.service nginx.service
        ConditionFileIsExecutable=/opt/srt-streamer-enhanced/network-tuning.sh

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        User=root
        Group=root # Added Group for consistency
        ExecStart=/opt/srt-streamer-enhanced/network-tuning.sh
        StandardOutput=journal
        StandardError=journal

        [Install]
        # Intentionally empty - pulled in by srt-streamer.service Wants=
        ```
    * **Application Service:** Create/Edit the main service file `/etc/systemd/system/srt-streamer.service`:
        ```ini
        [Unit]
        Description=SRT Streamer Enhanced - DVB Compliant App Server (Waitress)
        After=network.target network-online.target network-tuning.service nginx.service
        Wants=network-online.target network-tuning.service # Ensures tuning runs first

        [Service]
        Type=simple
        User=root # Review if non-root needed, ensure permissions align
        Group=root
        WorkingDirectory=/opt/srt-streamer-enhanced
        Environment="SECRET_KEY=paste_your_generated_secret_key_here" # <-- PASTE KEY HERE
        Environment="HOST=127.0.0.1"
        Environment="PORT=5000"
        Environment="THREADS=8" # Adjust as needed
        Environment="MEDIA_FOLDER=/opt/srt-streamer-enhanced/media"
        Environment="FLASK_ENV=production"
        ExecStart=/opt/venv/bin/python3 /opt/srt-streamer-enhanced/wsgi.py # Direct execution
        Restart=on-failure
        RestartSec=5s
        TimeoutStopSec=30s
        KillMode=mixed
        StandardOutput=journal
        StandardError=journal

        # --- Security Hardening (Optional but Recommended - Uncomment and adjust paths if needed) ---
        # PrivateTmp=true
        # ProtectSystem=strict
        # ProtectHome=true
        # NoNewPrivileges=true
        # CapabilityBoundingSet=CAP_NET_BIND_SERVICE # May need adjustment
        # ReadWritePaths=/opt/srt-streamer-enhanced/media /var/log/srt-streamer /opt/srt-streamer-enhanced/app/data

        [Install]
        WantedBy=multi-user.target
        ```
    * **Paste your generated `SECRET_KEY`** into the `Environment=` line in `/etc/systemd/system/srt-streamer.service`.
    * **Reload systemd, enable and start the *main* service:**
        ```bash
        sudo systemctl daemon-reload
        sudo systemctl enable srt-streamer.service # Do NOT enable network-tuning.service directly
        sudo systemctl start srt-streamer.service
        ```

6.  **Verify:** Check service status (`systemctl status srt-streamer.service network-tuning.service`), logs (`journalctl -u srt-streamer.service`, `/var/log/srt-streamer/srt_streamer.log`), and access the web UI via the Nginx address.

## Usage Workflow

1.  **Access & Login:** Open the application URL, log in via NGINX Basic Auth.
2.  **Dashboard (`/`):** View system status, active streams. Use form to start **Listener** streams (select port, file, latency, overhead (1-99%), encryption, QoS). Use `Browse` modal for file selection. *** UPDATED ***
3.  **Start Caller (`/caller`):** Navigate here to start **Caller** streams (specify target host/port, select file, latency, overhead (1-99%), encryption, QoS). Use `Browse` modal for file selection. *** UPDATED ***
4.  **Network Test (`/network_test`):** Select mode (Closest [TCP], Regional [TCP], Manual [TCP/UDP]), run test, view results (RTT, Bandwidth, Loss/Jitter [UDP only]) & Haivision-based recommendations (may be estimated if loss not directly measured). Click "Apply..." to pre-fill Listener form on dashboard. *** UPDATED Network Test Logic ***
5.  **View Details (`/stream/<key>`):** Click "Details" on dashboard. Monitor live stats (Bitrate, RTT, Loss %, Packet Counters, etc.), charts, connection status (including inferred caller status). Access debug info. *** UPDATED ***
6.  **Stop Streams:** Use "Stop" buttons on dashboard or details page.

## Configuration & Tuning Tips (from SRT Guide)

* **SRT Latency:** Determines buffer size for jitter and retransmissions. Set based on RTT (e.g., 4x RTT) and network stability. Higher value of sender/receiver setting is used. Adjust based on buffer monitoring.
* **Bandwidth Overhead:** Reserve extra bandwidth (**1-99%**) for packet recovery. Higher loss needs more overhead. Ensure total bandwidth fits link capacity. Start around 25% and adjust based on observed loss and retransmissions on the stats page. *** CHANGED ***
* **Quality of Service (QoS):** The `qos=true` URI parameter (enabled via checkbox) attempts to set DSCP network flags. Its effectiveness depends entirely on whether the intermediate network devices respect these flags. May have no effect on standard internet paths. *** ADDED ***
* **Monitoring Buffers (Stream Details Page):**
    * **Sender:** Consistent high Send Buffer Level often means bitrate too high or overhead too low. Occasional spikes might be handled by increasing Latency.
    * **Receiver:** Frequent drops to zero suggest bitrate too high. Occasional drops might need more Latency.
* **Packet Loss:** Monitor Lost/Skipped packets. Increase Latency for slow/jitter-related increases. Lower Bitrate or increase Overhead for large jumps/bursts.

## References

* [Haivision SRT Protocol Deployment Guide v1.5.x (PDF)](https://github.com/nt74/srt-streamer-enhanced/blob/main/docs/SRT%20Deployment%20Guide-v1-20250328_232802.pdf)
* [SRT Alliance](https://www.srtalliance.org/)
* [SRT GitHub Repository](https://github.com/Haivision/srt)

---
