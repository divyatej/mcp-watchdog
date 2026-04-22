"""mcp-trident — runtime security proxy for MCP tool calls."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

try:
    __version__ = _version("mcp-trident")
except PackageNotFoundError:
    __version__ = "unknown"

__author__ = "Divyatej Akella"