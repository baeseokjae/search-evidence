"""Stdio-only MCP. Paths, hosts and credentials are fixed by a local profile."""

from __future__ import annotations

from typing import Annotated, Literal

import anyio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import Profile
from .core import Result, canonical, failure
from .service import Service


class Inputs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Empty(Inputs):
    pass


class Page(Inputs):
    limit: int = Field(50, ge=1, le=500)
    cursor: str | None = Field(None, max_length=1024)


class Status(Inputs):
    remote: bool = False


URLText = Annotated[str, Field(min_length=1, max_length=4096)]


class Collect(Inputs):
    start: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$", max_length=10)
    end: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$", max_length=10)
    sources: list[Literal["gsc", "bing"]] = Field(default=["gsc", "bing"], min_length=1, max_length=2)
    tables: list[Literal["totals", "pages", "queries", "daily", "page_queries"]] = Field(
        default=["totals", "pages", "queries"], min_length=1, max_length=5
    )
    daily: bool = True
    resume: str | None = Field(None, max_length=128)
    page_url: str | None = Field(None, max_length=4096)


class Traffic(Page):
    source: Literal["gsc", "bing", "ga4", "csv"] = "gsc"
    table: str = Field("pages", max_length=60)
    snapshot_id: str | None = Field(None, pattern=r"^[a-f0-9]{64}$")
    url: str | None = Field(None, max_length=4096)


class Compare(Page):
    before: str = Field(pattern=r"^[a-f0-9]{64}$")
    after: str = Field(pattern=r"^[a-f0-9]{64}$")


class Protect(Page):
    urls: list[URLText] | None = Field(None, max_length=2000)


class Prioritize(Page):
    audit_id: str = Field(pattern=r"^[a-f0-9]{64}$")


class Audit(Page):
    audit_id: str | None = Field(None, pattern=r"^[a-f0-9]{64}$")


class Inspect(Inputs):
    urls: list[URLText] = Field(min_length=1, max_length=100)


class Verify(Page):
    manifest_id: str | None = Field(None, pattern=r"^[a-f0-9]{64}$")
    verification_id: str | None = Field(None, pattern=r"^[a-f0-9]{64}$")
    cache_check: bool = False


class Report(Inputs):
    audit_id: str | None = Field(None, pattern=r"^[a-f0-9]{64}$")
    verification_id: str | None = Field(None, pattern=r"^[a-f0-9]{64}$")


SPECS = {
    "search_status": (
        Status,
        True,
        True,
        "Show local availability and optionally check account/property access.",
    ),
    "search_collect": (
        Collect,
        False,
        True,
        "Collect read-only Google/Bing reports into private local storage.",
    ),
    "search_traffic": (Traffic, True, False, "Read one explicit snapshot; missing rows are unknown."),
    "search_compare": (Compare, True, False, "Compare compatible equal-length Google periods."),
    "search_protect_urls": (
        Protect,
        True,
        False,
        "Show raw URLs protected by any historical positive clicks.",
    ),
    "search_prioritize": (
        Prioritize,
        True,
        False,
        "Prioritize audit findings while preserving protected URLs.",
    ),
    "search_inspect_urls": (
        Inspect,
        False,
        True,
        "Read indexed Google/Bing records and persist observations.",
    ),
    "search_audit_content": (Audit, False, False, "Audit the configured content root; never edit its files."),
    "search_verify_live": (Verify, False, True, "Compare a registered reviewed build with public live HTML."),
    "search_render_report": (
        Report,
        False,
        False,
        "Write JSON, safe CSV and escaped HTML under private state.",
    ),
}


def build_server(profile: Profile) -> Server:
    # Initialization happens once before serving read-only tools.
    initial = Service(profile)
    initial.close()

    async def list_tools(ctx, params):
        return ListToolsResult(
            tools=[
                Tool(
                    name=name,
                    description=desc,
                    input_schema=model.model_json_schema(),
                    output_schema=Result.model_json_schema(),
                    annotations=ToolAnnotations(
                        read_only_hint=readonly,
                        destructive_hint=False,
                        idempotent_hint=readonly,
                        open_world_hint=external,
                    ),
                )
                for name, (model, readonly, external, desc) in SPECS.items()
            ]
        )

    def call(name, arguments):
        if name not in SPECS:
            return failure("unknown_tool")
        try:
            args = SPECS[name][0].model_validate(arguments or {}).model_dump()
        except ValidationError:
            return failure("invalid_arguments")
        service = Service(profile)
        try:
            return service.invoke(name, args)
        finally:
            service.close()

    async def call_tool(ctx, params):
        result = await anyio.to_thread.run_sync(call, params.name, params.arguments)
        value = result.model_dump()
        return CallToolResult(
            content=[TextContent(text=canonical(value).decode())],
            structured_content=value,
            is_error=not result.ok,
        )

    return Server(
        "search-evidence",
        version="0.1.0",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
        instructions="Use evidence timestamps and coverage. Missing is not zero. Keep protected URLs.",
    )


async def serve(profile: Profile):
    server = build_server(profile)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def run(profile: Profile):
    anyio.run(serve, profile)
