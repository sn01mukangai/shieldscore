#!/usr/bin/env python3
"""
Command Center — Master Dashboard for all operations
Single endpoint that serves status for everything we're doing.
"""

from flask import Flask, jsonify, send_from_directory
from datetime import datetime
import json
import os
import glob

app = Flask(__name__, static_folder='static', static_url_path='/static')

WORKSPACE = '/root/.openclaw/workspace'
RESULTS = '/root/tools/results'
SKILLS_DIR = '/root/.openclaw/workspace/skills'

def get_toolkit_status():
    """Check which tools are installed."""
    tools = {
        'subfinder': '/root/go/bin/subfinder',
        'httpx': '/root/go/bin/httpx',
        'nuclei': '/root/go/bin/nuclei',
        'waybackurls': '/root/go/bin/waybackurls',
        'gau': '/root/go/bin/gau',
        'jadx': '/usr/local/bin/jadx',
        'apktool': '/usr/local/bin/apktool',
    }
    status = {}
    for name, path in tools.items():
        status[name] = 'installed' if os.path.exists(path) else 'missing'
    return status

def get_skills():
    """List all installed skills."""
    skills = []
    if os.path.exists(SKILLS_DIR):
        for d in sorted(os.listdir(SKILLS_DIR)):
            meta_path = os.path.join(SKILLS_DIR, d, '_meta.json')
            skill_path = os.path.join(SKILLS_DIR, d, 'SKILL.md')
            meta = {}
            desc = ''
            if os.path.exists(meta_path):
                try:
                    meta = json.load(open(meta_path))
                except:
                    pass
            if os.path.exists(skill_path):
                with open(skill_path) as f:
                    lines = f.readlines()
                    for line in lines[:15]:
                        if 'description:' in line.lower():
                            desc = line.split(':', 1)[-1].strip().strip('"').strip("'")
                            break
            skills.append({'name': d, 'description': desc[:100], 'version': meta.get('version', '?')})
    return skills

def get_targets():
    """Scan for recon results."""
    targets = []
    if os.path.exists(RESULTS):
        for d in sorted(os.listdir(RESULTS)):
            target_dir = os.path.join(RESULTS, d)
            if os.path.isdir(target_dir):
                subs = len(open(os.path.join(target_dir, 'subs.txt')).readlines()) if os.path.exists(os.path.join(target_dir, 'subs.txt')) else 0
                live = len(open(os.path.join(target_dir, 'live.txt')).readlines()) if os.path.exists(os.path.join(target_dir, 'live.txt')) else 0
                urls = len(open(os.path.join(target_dir, 'wayback.txt')).readlines()) if os.path.exists(os.path.join(target_dir, 'wayback.txt')) else 0
                targets.append({
                    'domain': d,
                    'subdomains': subs,
                    'live_hosts': live,
                    'urls': urls
                })
    return targets

@app.route('/')
def index():
    return send_from_directory('static', 'dashboard.html')

@app.route('/api/status')
def status():
    return jsonify({
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'version': '1.0.0',
        'toolkit': get_toolkit_status(),
        'skills': get_skills(),
        'targets': get_targets(),
        'services': {
            'shieldscore': {'port': 5000, 'status': 'running'},
            'command_center': {'port': 5001, 'status': 'running'}
        },
        'stats': {
            'total_skills': len(get_skills()),
            'total_targets': len(get_targets()),
            'tools_installed': sum(1 for v in get_toolkit_status().values() if v == 'installed'),
            'tools_missing': sum(1 for v in get_toolkit_status().values() if v == 'missing')
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
