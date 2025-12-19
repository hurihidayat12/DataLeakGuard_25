# app.py
# Human Error Security Detector - Full Version
# Upload folder/file -> Scan -> Dashboard

from flask import Flask, render_template, request, redirect, url_for
import os
import re
import json
from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
REPORT_FOLDER = 'reports'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

SENSITIVE_KEYWORDS = [
    'password', 'passwd', 'apikey', 'api_key',
    'secret', 'token', 'private_key'
]

ALLOWED_EXT = ('.txt', '.env', '.cfg', '.log', '.php', '.json')

# ---------------- SCAN ENGINE ----------------
def scan_file(path):
    findings = []
    try:
        with open(path, 'r', errors='ignore') as f:
            for idx, line in enumerate(f, start=1):
                for key in SENSITIVE_KEYWORDS:
                    if key in line.lower():
                        findings.append({
                            'file': path,
                            'line': idx,
                            'keyword': key,
                            'risk': 'HIGH'
                        })
    except:
        pass
    return findings


def scan_directory(folder):
    results = []
    for root, _, files in os.walk(folder):
        for file in files:
            if file.lower().endswith(ALLOWED_EXT):
                full_path = os.path.join(root, file)
                results.extend(scan_file(full_path))
    return results


def save_report(results):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'report_{timestamp}.json'
    path = os.path.join(REPORT_FOLDER, filename)

    summary = {
        'timestamp': timestamp,
        'total_findings': len(results),
        'high_risk': len(results),
        'results': results
    }

    with open(path, 'w') as f:
        json.dump(summary, f, indent=4)

    return summary

# ---------------- ROUTES ----------------
@app.route('/')
def index():
    reports = sorted(os.listdir(REPORT_FOLDER), reverse=True)
    return render_template('index.html', reports=reports)


@app.route('/upload', methods=['POST'])
def upload():
    files = request.files.getlist('files')
    if not files:
        return redirect(url_for('index'))

    for file in files:
        save_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(save_path)

    results = scan_directory(UPLOAD_FOLDER)
    save_report(results)

    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    latest = sorted(os.listdir(REPORT_FOLDER))[-1]
    with open(os.path.join(REPORT_FOLDER, latest)) as f:
        data = json.load(f)
    return render_template('dashboard.html', data=data)


if __name__ == '__main__':
    app.run(debug=True)
