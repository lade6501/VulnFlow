"""
src/vulnflow/mcp_servers/fastmcp.py
FastMCP server framework exposing typed tools over the Model Context Protocol (MCP).
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
import sys
from typing import Any, Callable, Dict, List, Optional, get_args, get_origin, get_type_hints

logger = logging.getLogger("vulnflow.mcp_servers.fastmcp")


def _python_type_to_json_schema(py_type: Any) -> Dict[str, Any]:
    """Map Python type annotation to JSON schema snippet."""
    origin = get_origin(py_type)
    if origin is list or py_type is list:
        return {"type": "array"}
    if origin is dict or py_type is dict:
        return {"type": "object"}
    if py_type is str:
        return {"type": "string"}
    if py_type is int:
        return {"type": "integer"}
    if py_type is float:
        return {"type": "number"}
    if py_type is bool:
        return {"type": "boolean"}
    # Handle Optional / Union[T, None]
    if origin is not None:
        args = [a for a in get_args(py_type) if a is not type(None)]
        if len(args) == 1:
            return _python_type_to_json_schema(args[0])
    return {"type": "string"}


def _build_input_schema(func: Callable[..., Any]) -> Dict[str, Any]:
    """Generate MCP inputSchema object from function type signatures."""
    sig = inspect.signature(func)
    hints = {}
    try:
        hints = get_type_hints(func)
    except Exception:
        pass

    properties: Dict[str, Any] = {}
    required: List[str] = []

    for name, param in sig.parameters.items():
        if name in ("self", "cls"):
            continue
        param_type = hints.get(name, Any)
        schema = _python_type_to_json_schema(param_type)
        properties[name] = schema

        # If no default value, mark required
        if param.default is inspect.Parameter.empty:
            required.append(name)

    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }


class ToolDefinition:
    """Represents a registered MCP tool with schema and executable target."""

    def __init__(
        self,
        name: str,
        description: str,
        func: Callable[..., Any],
        input_schema: Dict[str, Any],
    ) -> None:
        self.name = name
        self.description = description
        self.func = func
        self.input_schema = input_schema

    def to_mcp_dict(self) -> Dict[str, Any]:
        """Format as standard MCP tools/list tool entry."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class FastMCP:
    """
    Standard Model Context Protocol (MCP) server instance.
    Supports tool registration via @mcp.tool(), typed schema reflection,
    and JSON-RPC 2.0 stdio transport conforming to MCP 2024-11-05.
    """

    def __init__(self, name: str, description: Optional[str] = None) -> None:
        self.name = name
        self.description = description or f"VulnFlow MCP Server: {name}"
        self._tools: Dict[str, ToolDefinition] = {}

    def tool(
        self,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator registering a function as a typed MCP tool."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or func.__name__
            tool_desc = (description or func.__doc__ or f"MCP tool {tool_name}").strip()
            input_schema = _build_input_schema(func)

            tool_def = ToolDefinition(
                name=tool_name,
                description=tool_desc,
                func=func,
                input_schema=input_schema,
            )
            self._tools[tool_name] = tool_def

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                return func(*args, **kwargs)

            # Attach metadata
            setattr(wrapper, "__mcp_tool__", tool_def)
            setattr(wrapper, "__mcp_server__", self)
            return wrapper

        return decorator

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return all registered MCP tools conforming to tools/list schema."""
        return [t.to_mcp_dict() for t in self._tools.values()]

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        """Invoke an MCP tool by name with arguments."""
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' not found on MCP server '{self.name}'")
        tool_def = self._tools[name]
        args = arguments or {}
        return tool_def.func(**args)

    def run_stdio(self) -> None:
        """Execute JSON-RPC 2.0 stdio server loop for standard MCP clients."""
        logger.info("Starting MCP stdio server '%s'...", self.name)
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                continue

            req_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})

            # 1. MCP initialize
            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": self.name, "version": "1.0.0"},
                    },
                }
            # 2. notifications/initialized
            elif method == "notifications/initialized":
                continue
            # 3. ping
            elif method == "ping":
                response = {"jsonrpc": "2.0", "id": req_id, "result": {}}
            # 4. tools/list
            elif method == "tools/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": self.list_tools()},
                }
            # 5. tools/call
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                try:
                    res = self.call_tool(tool_name, arguments)
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": json.dumps(res)}],
                            "isError": False,
                        },
                    }
                except Exception as exc:
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": str(exc)}],
                            "isError": True,
                        },
                    }
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method '{method}' not found"},
                }

            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

    def run(self, transport: str = "stdio") -> None:
        """Run the MCP server over the specified transport."""
        if transport == "stdio":
            self.run_stdio()
        else:
            raise ValueError(f"Unsupported transport '{transport}'")
