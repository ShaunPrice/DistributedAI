# SPDX-License-Identifier: AGPL-3.0-only
"""Compatibility alias for the persistence implementation."""
import sys
from .persistence import billing as _implementation
sys.modules[__name__] = _implementation
