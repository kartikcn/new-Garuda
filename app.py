#!/usr/bin/env python3
from flask import Flask, render_template, request, session, jsonify
import subprocess
import json
import os
from datetime import datetime
from uuid import uuid4

app = Flask(__name__)
app.secret_key = 'super-secret-key'  # Required for session

# === Scan history storage ===
SCAN_HISTORY_FILE = 'scan_history.json'

def load_history():
    if os.path.exists(SCAN_HISTORY_FILE):
        with open(SCAN_HISTORY_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_history(data):
    with open(SCAN_HISTORY_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# 🔍 Explain common ports
def explain_port(port, service):
    explanations = {
        "22": "SSH login – secure this with key-based auth.",
        "443": "HTTPS – ensure SSL cert is valid.",
        "21": "FTP – prefer SFTP instead.",
        "23": "Telnet – insecure. Disable it.",
        "3306": "MySQL – never expose to internet.",
        "25": "SMTP – use TLS if running.",
        "80": "HTTP – serve HTTPS instead.",
    }
    return explanations.get(port, "Check this port's service and ensure it's secure.")

# 🧠 Parse Nmap Output
def parse_nmap_output(output):
    lines = output.split('\n')
    results = []
    start = False

    for line in lines:
        if "PORT" in line and "STATE" in line:
            start = True
            continue
        if start and line.strip() == "":
            break
        if start:
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                state = parts[1]
                service = parts[2]
                explanation = explain_port(port.split("/")[0], service)
                msg = f"<strong>{port}</strong> is <strong>{state.upper()}</strong> and running <strong>{service.upper()}</strong>. {explanation}"
                results.append(msg)
    return results

# 🏠 Home Page
@app.route("/")
def home():
    return render_template("index.html", results=None, target=None)

# 🔍 Scan Route (Ensure results appear in the original Garuda interface)
@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    advanced = request.form.get("advanced") == "on"
    results = []

    if not target:
        results.append("⚠ No target specified.")
        return render_template("index.html", results=results, target=target)

    try:
        command = ['nmap', '-A', '-O', '-Pn', target] if advanced else ['nmap', '-Pn', target]
        scan_output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        current_scan = parse_nmap_output(scan_output)
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Load previous scan from file
        history = load_history()
        previous_data = history.get(target)
        previous_scan = previous_data['results'] if previous_data else None
        previous_time = previous_data['time'] if previous_data else None

        # Save in session for /compare route
        if 'last_scans' not in session:
            session['last_scans'] = []
        session['last_scans'].append({
            'id': str(uuid4()),
            'target': target,
            'time': scan_time,
            'results': current_scan
        })
        session['last_scans'] = session['last_scans'][-2:]

        # Inline comparison (optional)
        if previous_scan:
            changes = []
            for entry in current_scan:
                if entry not in previous_scan:
                    changes.append(f"🆕 New: {entry}")
            for entry in previous_scan:
                if entry not in current_scan:
                    changes.append(f"❌ Removed: {entry}")
            if not changes:
                changes.append("✅ No changes since last scan.")
            results.append(f"<strong>🔁 Comparison with last scan on {previous_time}:</strong>")
            results.extend(changes)

        results.append(f"<strong>📄 Current Scan at {scan_time}:</strong>")
        results.extend(current_scan)

        # Save to file history
        history[target] = {
            'results': current_scan,
            'time': scan_time
        }
        save_history(history)

    except subprocess.CalledProcessError as e:
        results = [f"⚠ Scan failed: {e.output}"]
    except Exception as e:
        results = [f"⚠ Unexpected error: {str(e)}"]

    return render_template("index.html", results=results, target=target)

# 📊 Compare Route (Still supports comparisons)
@app.route("/compare")
def compare():
    scans = session.get('last_scans', [])

    if len(scans) < 2:
        return render_template("compare.html", message="Not enough scans to compare.")

    scan1, scan2 = scans[-2], scans[-1]
    diff = {
        "new": list(set(scan2['results']) - set(scan1['results'])),
        "gone": list(set(scan1['results']) - set(scan2['results']))
    }

    return render_template("compare.html", scan1=scan1, scan2=scan2, diff=diff)

# 🚀 Run
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)
