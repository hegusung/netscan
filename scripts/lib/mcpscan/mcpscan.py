from __future__ import annotations

import os.path
import re
import json
import traceback
from time import sleep
from utils.output import Output
from utils.db import DB
import requests
import sys
import ssl


import itertools
import json
from typing import Any, Optional


#MCP_JSON = {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"roots":{},"sampling":{}},"clientInfo":{"name":"my-client","version":"1.0"}}}
#HEADERS = {"Accept": "application/json, text/event-stream"}

PROTOCOL_VERSION = "2025-06-18"


def mcpscan_worker(target, actions, timeout):
    try:
        mcp_client = MCPClient(method=target['method'], hostname=target['hostname'], port=target['port'], uri=target['path'])

        mcp_server_data = mcp_client.connect()

        Output.write({'target': '%s:%d' % (target['hostname'], target['port']), 'message': "MCP server:  %s  (%s)" % (mcp_server_data[0].ljust(30), mcp_server_data[1])})

        if 'list_tools' in actions:
            tools = mcp_client.list_tools()
            print(tools)

        if 'list_resources' in actions:
            resources = mcp_client.list_resources()
            print(resources)


        mcp_client.close()

    except MCPError:
        pass
    except Exception as e:
        raise e



class MCPError(Exception):
    """Raised on transport errors or JSON-RPC error responses."""
 
    def __init__(self, message: str, code: Optional[int] = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data
 
 
class MCPClient:
    def __init__(
        self,
        method: str = "http",          # URL scheme: "http" or "https"
        hostname: str = "127.0.0.1",
        port: Optional[int] = 8000,    # None = scheme default (80/443)
        uri: str = "/mcp",
        headers: Optional[dict] = None,  # e.g. {"Authorization": "Bearer ..."}
        timeout: float = 30.0,
        verify: bool = True,             # set False for self-signed certs
        client_name: str = "python-mcp-client",
        client_version: str = "1.0.0",
    ):
        if method not in ("http", "https"):
            raise ValueError("method must be 'http' or 'https'")
        host_port = f"{hostname}:{port}" if port else hostname
        self.url = f"{method}://{host_port}/{uri.lstrip('/')}"
        self.timeout = timeout
        self.client_info = {"name": client_name, "version": client_version}
 
        self._http = requests.Session()
        self._http.verify = verify
        self._extra_headers = dict(headers or {})
        self._ids = itertools.count(1)
 
        self.session_id: Optional[str] = None
        self.protocol_version: Optional[str] = None
        self.server_info: dict = {}
        self.capabilities: dict = {}
 
    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def connect(self) -> tuple[str, str]:
        """Handshake with the server. Returns (server_name, server_version)."""
        result = self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},  # we implement no client features (sampling, roots...)
                "clientInfo": self.client_info,
            },
        )
        self.protocol_version = result.get("protocolVersion", PROTOCOL_VERSION)
        self.capabilities = result.get("capabilities", {})
        self.server_info = result.get("serverInfo", {})
        self._notify("notifications/initialized")
        return self.server_info.get("name", ""), self.server_info.get("version", "")
 
    def list_tools(self) -> list[dict]:
        return self._paginate("tools/list", "tools")
 
    def call_tool(self, name: str, arguments: Optional[dict] = None) -> dict:
        """Execute a tool. Returns the raw result ({"content": [...], "isError": bool})."""
        return self._request("tools/call", {"name": name, "arguments": arguments or {}})
 
    def list_resources(self) -> list[dict]:
        return self._paginate("resources/list", "resources")
 
    def read_resource(self, uri: str) -> list[dict]:
        """Query a resource by URI. Returns its list of contents (text or blob)."""
        return self._request("resources/read", {"uri": uri}).get("contents", [])
 
    def close(self) -> None:
        """End the session (HTTP DELETE) if the server issued a session id."""
        if self.session_id:
            try:
                self._http.delete(self.url, headers=self._headers(), timeout=self.timeout)
            except requests.RequestException:
                pass
            self.session_id = None
        self._http.close()
 
    @staticmethod
    def text_of(tool_result: dict) -> str:
        """Convenience: concatenate the text parts of a tools/call result."""
        return "\n".join(
            part.get("text", "")
            for part in tool_result.get("content", [])
            if part.get("type") == "text"
        )
 
    def __enter__(self) -> "MCPClient":
        return self
 
    def __exit__(self, *exc) -> None:
        self.close()
 
    # ------------------------------------------------------------------ #
    # JSON-RPC plumbing
    # ------------------------------------------------------------------ #
    def _headers(self) -> dict:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self._extra_headers,
        }
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            h["MCP-Protocol-Version"] = self.protocol_version
        return h
 
    def _request(self, method: str, params: Optional[dict] = None) -> dict:
        req_id = next(self._ids)
        payload: dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
 
        msg = self._post(payload, req_id)
        if msg is None:
            raise MCPError(f"No response to '{method}'")
        if "error" in msg:
            err = msg["error"]
            raise MCPError(err.get("message", "unknown error"), err.get("code"), err.get("data"))
        return msg.get("result", {})
 
    def _notify(self, method: str, params: Optional[dict] = None) -> None:
        payload: dict = {"jsonrpc": "2.0", "method": method}  # no id => notification
        if params is not None:
            payload["params"] = params
        self._post(payload, None)
 
    def _post(self, payload: dict, req_id: Optional[int]) -> Optional[dict]:
        try:
            resp = self._http.post(
                self.url,
                data=json.dumps(payload),
                headers=self._headers(),
                timeout=self.timeout,
                stream=True,
            )
        except requests.RequestException as e:
            raise MCPError(f"Connection failed: {e}") from e
 
        with resp:
            if resp.status_code >= 400:
                raise MCPError(f"HTTP {resp.status_code}: {resp.text[:300]}", resp.status_code)
 
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self.session_id = sid
 
            if resp.status_code == 202 or req_id is None:
                return None  # notification accepted, nothing to read
 
            ctype = resp.headers.get("Content-Type", "")
            if "text/event-stream" in ctype:
                return self._read_sse(resp, req_id)
 
            body = resp.json()
            if isinstance(body, list):  # JSON-RPC batch
                body = next((m for m in body if m.get("id") == req_id), None)
            return body
 
    @staticmethod
    def _read_sse(resp: requests.Response, req_id: int) -> dict:
        """Read an SSE stream until the response matching req_id arrives.
 
        Server notifications and server-initiated requests on the stream
        are ignored (this client doesn't implement sampling/elicitation).
        """
        resp.encoding = "utf-8"
        data_lines: list[str] = []
        for line in resp.iter_lines(decode_unicode=True):
            if line is None:
                continue
            if line == "":  # blank line = end of one event
                if data_lines:
                    msg = json.loads("\n".join(data_lines))
                    data_lines = []
                    if msg.get("id") == req_id and ("result" in msg or "error" in msg):
                        return msg
                continue
            if line.startswith(":"):  # SSE comment / keep-alive
                continue
            if line.startswith("data:"):
                data_lines.append(line[5:][1:] if line[5:].startswith(" ") else line[5:])
        raise MCPError("Stream ended without a response")
 
    def _paginate(self, method: str, key: str) -> list[dict]:
        items: list[dict] = []
        cursor: Optional[str] = None
        while True:
            result = self._request(method, {"cursor": cursor} if cursor else None)
            items.extend(result.get(key, []))
            cursor = result.get("nextCursor")
            if not cursor:
                return items
 
 

