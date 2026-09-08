# SPDX-License-Identifier: AGPL-3.0-only
"""Compatibility imports. New code uses application contracts or persistence adapters."""
from .persistence import workspace as _implementation


def __getattr__(name):
    return getattr(_implementation, name)


def __dir__():
    return sorted(set(globals()) | set(dir(_implementation)))
