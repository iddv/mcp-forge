---
name: mcp-forge
description: "Build MCP (Model Context Protocol) servers in Python with the mcp-forge CLI: scaffold a project, add protocol features (tools, resources, prompts, elicitation, sampling, auth, HTTP, MCP Apps), test it, and package it as a Claude Code plugin, Agent Skill, MCPB bundle, or MCP Registry entry. Use when the user wants to create, extend, or ship an MCP server."
argument-hint: "[what the server should do]"
---

# Building MCP servers with mcp-forge

mcp-forge generates Python MCP servers on the official `mcp` SDK 2.x (`MCPServer`,
protocol revision 2026-07-28, backwards compatible with handshake-era clients).

## Setup

If `mcp-forge --version` fails, install it with `uv tool install mcp-forge`, falling back to `pipx install mcp-forge`.
It needs version 3.0 or later. Older versions generate `FastMCP` code that breaks on `mcp` 2.x.

## Workflow

1. **Scaffold**: `mcp-forge new <name> -d "<one-line description>" [--with f1,f2]`,
   then `cd <name> && pip install -e ".[test]"` (or `uv sync --extra test`).
2. **Add features before writing code**: `mcp-forge add <feature> [<feature> ...]`. This is idempotent.
   Pick features from the table below (or run `mcp-forge features`). Each one inserts working, tested
   example code into `server.py`, showing the correct SDK 2.x API, so you don't need to read SDK source.
   Adapt the examples to the user's real domain, then delete any demo tools you didn't reuse.
3. **Write the real tools** in `server.py`. Follow the patterns the snippets establish (below).
4. **Test**: `pytest`. The generated tests use the in-process `Client(mcp)`. Add a test for every tool.
   Use `mcp dev server.py` for the MCP Inspector.
5. **Register**: `mcp-forge install` (auto-detects clients) or `mcp-forge install --client claude-code`.
6. **Distribute** (optional): `mcp-forge add plugin` (Claude Code plugin + skill + marketplace),
   `mcp-forge add mcpb` (Claude Desktop bundle), `mcp-forge add docker` (container serving HTTP),
   `mcp-forge add registry` (MCP Registry `server.json`).
   Add distribution features **last**: the generated skill and MCPB manifest list the tools present at
   generation time. To regenerate, delete the file and re-run `add`.

## Choosing features

| User need | Feature |
|---|---|
| Expose read-only data / documents | `resources`, `resource-templates` (parameterised URIs) |
| Reusable prompt templates / slash commands | `prompts`; add `completions` for argument autocomplete |
| Tools that modify or delete things | `annotations` (`destructive_hint`, `read_only_hint`, ...) |
| Bad input / not-found errors the model should see | `errors` (`ToolError`); almost every server wants this |
| Typed / JSON results | `structured-output` (return a pydantic model) |
| Images, files, links to large results | `media` (Image content, `ResourceLink`) |
| Long-running tools | `context` (progress reporting) |
| Ask the user to confirm or fill a form | `elicitation` |
| Need an LLM inside a tool | `sampling` (deprecated in spec 2026-07-28; prefer returning data) |
| Know the user's open workspace | `roots` (deprecated; prefer explicit path arguments) |
| Data that changes / tools enabled at runtime | `notifications` (resource updated, tools list changed) |
| DB pools, HTTP clients, loaded models | `lifespan` |
| Timing, audit logging, rate limiting | `middleware` |
| Remote / hosted server | `http` (Streamable HTTP, `--http`, `MCP_HOST`/`MCP_PORT`), then `auth` (OAuth 2.1 resource server) and `docker` |
| Rich interactive UI in the host | `apps` (MCP Apps, `ui://` resources) |

## SDK 2.x patterns (don't use 1.x idioms)

- Import from `mcp.server.mcpserver` (`MCPServer`, `Context`, `Resolve`, `Elicit`, `Sample`,
  `ListRoots`, `Image`). `mcp.server.fastmcp` no longer exists.
- Don't call `ctx.elicit()`, `ctx.session.create_message()`, or `ctx.session.list_roots()` directly in
  tools. They fail on stateless 2026-07-28 connections. Use a `Resolve` parameter instead:
  `answer: Annotated[ElicitationResult[Model], Resolve(resolver)]`, where the resolver returns
  `Elicit(...)`, `Sample(...)` or `ListRoots()`.
- Protocol logging (`ctx.info`) is deprecated. Log with the stdlib `logging` module and report progress with
  `await ctx.report_progress(done, total, message)`.
- Transport options (`host`, `port`, `stateless_http`) go to `mcp.run(...)`, not the `MCPServer(...)` constructor.
- Type fields are snake_case: `ToolAnnotations(read_only_hint=True)`, `result.structured_content`.
- Never print to stdout in a stdio server. stdout carries the protocol; log to stderr.
