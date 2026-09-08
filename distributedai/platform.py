# SPDX-License-Identifier: AGPL-3.0-only
"""Backward-compatible platform exports; runtime uses explicit layered wiring."""
from .presentation.platform import platform_app  # noqa: F401


def __getattr__(name):
    from .persistence import platform
    if name == "PlatformService":
        return platform.build_platform_service
    return getattr(platform, name)
