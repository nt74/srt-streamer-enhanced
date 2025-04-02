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
    * Clone or download source to `/opt/srt-streamer-enhanced`.
        ```bash
        # Example using git
        sudo git clone [https://github.com/nt74/srt-streamer-enhanced.git](https://github.com/nt74/srt-streamer-enhanced.git) /opt/srt-streamer-enhanced
        cd /opt/srt-streamer-enhanced
        ```

2.  **Install System Dependencies:**
    * Install Python 3, pip, venv, GStreamer (+ plugins `base`, `good`, `bad`, `ugly`, `libav`), PyGObject build dependencies (`gobject-introspection-devel`, `cairo-gobject-devel`, etc.), Nginx, curl, `iperf3`, `ping` (`iputils-ping`), `dig` (`dnsutils`/`bind-utils`), `ffmpeg`, `mediainfo`, `htpasswd` (`apache2-utils`/`httpd-tools`).
    * *(Keep specific package names for Debian/RHEL examples as provided)*

3.  **Set Up Python Environment:**
    * Create and activate virtual environment (e.g., `/opt/venv`).
        ```bash
        sudo python3 -m venv /opt/venv
        source /opt/venv/bin/activate
        ```
    * Install Python packages:
        ```bash
        pip install -r requirements.txt
        ```
    * Deactivate: `deactivate`

4.  **Configure Application:**
    * **Media Files:** Place `.ts` files in `/opt/srt-streamer-enhanced/media/` (create if needed).
    * **Log/Data Directories:** Ensure directories exist and have correct permissions (adjust owner if service runs as non-root):
        ```bash
        sudo mkdir -p /var/log/srt-streamer /opt/srt-streamer-enhanced/app/data /opt/srt-streamer-enhanced/media
        sudo chown root:root /var/log/srt-streamer /opt/srt-streamer-enhanced/app/data /opt/srt-streamer-enhanced/media
        # Ensure external_ip.txt exists and is writable by the process that updates it
        sudo touch /opt/srt-streamer-enhanced/app/data/external_ip.txt
        # Example: sudo chown <user_that_runs_script>:root /opt/srt-streamer-enhanced/app/data/external_ip.txt
        ```
    * **NGINX:** Configure reverse proxy for `http://127.0.0.1:5000`, set up Basic Auth with `htpasswd` (use a strong password for user `admin`, secure `/etc/nginx/.htpasswd` permissions). Test/restart Nginx.
    * **Flask Secret Key:** Generate (`openssl rand -hex 32`) and copy a strong key.

5.  **Set Up Systemd Services (Recommended):**
    * **Network Tuning Script:** Ensure `/opt/srt-streamer-enhanced/network-tuning.sh` is executable (`sudo chmod +x ...`).
    * **Network Tuning Service:** Create the file `/etc/systemd/system/network-tuning.service` with the following content:
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
        Group=root
        ExecStart=/opt/srt-streamer-enhanced/network-tuning.sh
        StandardOutput=journal
        StandardError=journal

        [Install]
        # This service is not typically enabled directly.
        # It's pulled in by the 'Wants=' directive in srt-streamer.service.
        # WantedBy=multi-user.target
        ```
    * **Application Service:** Create/Edit the main service file `/etc/systemd/system/srt-streamer.service` with the following content:
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
        # --- IMPORTANT: Replace with your generated key ---
        Environment="SECRET_KEY=paste_your_generated_secret_key_here"
        # --- Other Environment Variables ---
        Environment="HOST=127.0.0.1"
        Environment="PORT=5000"
        Environment="THREADS=8" # Adjust as needed
        Environment="MEDIA_FOLDER=/opt/srt-streamer-enhanced/media"
        Environment="FLASK_ENV=production"
        # --- Execution ---
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
        # CapabilityBoundingSet=CAP_NET_BIND_SERVICE # May need adjustment - likely not needed if User=root and running on port > 1024
        # ReadWritePaths=/opt/srt-streamer-enhanced/media /var/log/srt-streamer /opt/srt-streamer-enhanced/app/data # Explicitly allow writes

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

1.  **Access & Login:** Open URL, login via Basic Auth.
2.  **Dashboard (`/`):** View status, active streams. Start **Listener** streams (select port, file, latency, overhead (1-99%), encryption, QoS). Use `Browse`. *** UPDATED ***
3.  **Start Caller (`/caller`):** Start **Caller** streams (specify target host/port, select file, latency, overhead (1-99%), encryption, QoS). Use `Browse`. *** UPDATED ***
4.  **Network Test (`/network_test`):** Select mode (Closest [TCP], Regional [TCP], Manual [TCP/UDP]), run test, view results (RTT, Bandwidth, Loss/Jitter [UDP only]) & Haivision-based recommendations (may be estimated if loss not directly measured). Click "Apply..." to pre-fill Listener form. *** UPDATED Network Test Logic ***
5.  **View Details (`/stream/<key>`):** Click "Details" on dashboard. Monitor live stats, charts, connection status (incl. caller IP). Access debug info. *** UPDATED ***
6.  **Stop Streams:** Use "Stop" buttons.

## Configuration & Tuning Tips (from SRT Guide)

* **SRT Latency:** Buffer size (ms). Base on measured RTT and loss (Network Test helps). `Latency = RTT Multiplier * RTT`. Higher latency handles more jitter/loss but increases delay. Start with recommendation, monitor buffer stats on Details page.
* **Bandwidth Overhead:** Reserve extra bandwidth (**1-99%**) for recovery. Higher loss/retransmits need more overhead. Use Network Test recommendation as starting point. Monitor packet stats (retransmits, drops) on Details page. Ensure `Stream Bitrate * (1 + Overhead/100)` fits your network path capacity. *** UPDATED Range ***
* **Quality of Service (QoS):** Enabling the `qos=true` URI parameter (via checkbox) attempts to set DSCP network flags for prioritized packet handling. Its actual effect **depends entirely on intermediate network devices** respecting these flags. May have little to no effect on the public internet. *** ADDED ***
* **Monitoring Buffers (Stream Details Page):** Guide for tuning Latency.
    * *Sender Buffer:* High average level might indicate insufficient link bandwidth or too low Overhead %. Spikes might need more Latency.
    * *Receiver Buffer:* Frequent drops to near zero indicate insufficient Latency or network issues exceeding the buffer's capacity.
* **Packet Loss:** Monitor Lost/Dropped/Retransmitted packets. Increase Latency or Overhead based on patterns. Consistent high loss might require addressing the underlying network path.

## References

* [Haivision SRT Protocol Deployment Guide v1.5.x (PDF)](https://github.com/nt74/srt-streamer-enhanced/blob/main/docs/SRT%20Deployment%20Guide-v1-20250328_232802.pdf) [cite: 3]
* [SRT Alliance](https://www.srtalliance.org/)
* [SRT GitHub Repository](https://github.com/Haivision/srt)

---
