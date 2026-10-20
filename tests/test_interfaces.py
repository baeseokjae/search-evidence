import json
import os
import subprocess
import sys

import anyio
from conftest import gsc_snapshot
from mcp import Client, ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from search_evidence.mcp_server import build_server


def test_mcp_schema_annotations_and_error_envelope(profile, service):
    gsc_snapshot(service)

    async def scenario():
        async with Client(build_server(profile)) as client:
            response = await client.list_tools()
            assert len(response.tools) == 10
            for t in response.tools:
                assert t.output_schema["type"] == "object"
                assert t.annotations.destructive_hint is False
            annotations = {t.name: t.annotations.read_only_hint for t in response.tools}
            assert annotations["search_traffic"] is True
            assert annotations["search_collect"] is False and annotations["search_verify_live"] is False
            result = await client.call_tool("search_traffic", {})
            assert result.structured_content["data"] == service.traffic()
            bad = await client.call_tool("search_traffic", {"limit": 501})
            assert bad.is_error and bad.structured_content["error"]["code"] == "invalid_arguments"
            denied = await client.call_tool("search_audit_content", {"path": "/etc"})
            assert denied.is_error

    anyio.run(scenario)


def test_real_stdio_protocol_and_cli_parity(profile, service, tmp_path):
    gsc_snapshot(service)
    config = tmp_path / "profile.toml"
    config.write_text(f'site = "https://example.com/"\nstate_dir = "{profile.state_dir}"\n')
    base = [sys.executable, "-m", "search_evidence.cli", "--profile", str(config)]
    cli = subprocess.run(base + ["traffic"], capture_output=True, text=True, timeout=10, check=True)
    expected = json.loads(cli.stdout)

    async def scenario():
        params = StdioServerParameters(command=sys.executable, args=base[1:] + ["mcp"], env=dict(os.environ))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                result = await client.call_tool("search_traffic", {})
                assert result.structured_content == expected and result.is_error is False

    anyio.run(scenario)


def test_cli_failure_is_json_and_nonzero(tmp_path):
    r = subprocess.run(
        [sys.executable, "-m", "search_evidence.cli", "--profile", str(tmp_path / "absent.toml"), "status"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert r.returncode == 1 and json.loads(r.stdout)["error"]["code"] == "invalid_profile"
    assert "Traceback" not in r.stderr
