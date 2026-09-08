# SPDX-License-Identifier: AGPL-3.0-only
"""Compatibility alias for the presentation adapter."""
import sys
from .presentation import auth as _implementation
sys.modules[__name__] = _implementation
