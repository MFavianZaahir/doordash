from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Set default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'doordash.settings')

app = Celery('doordash')

# Using a string means the worker doesn’t have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Discover tasks from all registered Django app configs
app.autodiscover_tasks()
