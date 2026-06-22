"""
AWE MITM proxy package.

Public API
----------
ControlClient — send commands to a running proxy from the GUI process.
ProxyServer   — available for in-process use; NOT imported here at package
                level to avoid the runpy collision when the proxy is started
                via `python -m proxy.server`.
"""
from proxy._control import ControlClient

__all__ = ["ControlClient"]
