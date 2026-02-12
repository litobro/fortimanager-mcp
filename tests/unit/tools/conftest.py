"""Pytest configuration for tools unit tests."""

import os
import pytest
from unittest.mock import MagicMock, patch

# Set required environment variables before any imports
os.environ['FORTIMANAGER_HOST'] = 'test.example.com'
os.environ['FORTIMANAGER_TOKEN'] = 'test_token'
