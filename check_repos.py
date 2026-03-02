import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.append(os.getcwd())

# Setup Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "learning.settings")
import django
django.setup()

from db import run_query

repos = run_query("SELECT id, workspace_id, repo_full_name, webhook_secret, events_mask, is_active FROM github_repos", fetchall=True)
for r in repos:
    print(f"WS={r['workspace_id']} REPO={r['repo_full_name']} SECRET='{r['webhook_secret']}' MASK={r['events_mask']}")
if not repos:
    print("No repos found.")
