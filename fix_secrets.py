import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.append(os.getcwd())

# Setup Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "learning.settings")
import django
django.setup()

from django.conf import settings
from db import run_query

new_secret = settings.GITHUB_WEBHOOK_SECRET
print(f"Updating all repositories to use new secret: '{new_secret}'")

run_query("UPDATE github_repos SET webhook_secret = %s", (new_secret,))
print("Database updated.")
