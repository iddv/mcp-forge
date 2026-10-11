"""Add MCP features to an existing server project."""

import ast
import re
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Callable, Dict, List, Optional

from mcp_forge import distribute


SNIPPETS = files("mcp_forge") / "snippets"

SERVER_CALL = re.compile(r"^mcp\s*=\s*(MCPServer|FastMCP)\(", re.MULTILINE)
MAIN_MARKER = "\ndef main():"
NAME_MARKER = 'if __name__ == "__main__":'

DEFAULT_MAIN = "def main():\n    mcp.run()\n"
HTTP_MAIN = '''def main():
    import argparse

    parser = argparse.ArgumentParser(description=mcp.instructions)
    parser.add_argument("--http", action="store_true", help="Serve over Streamable HTTP instead of stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--stateless", action="store_true", help="Stateless HTTP (horizontal scaling)")
    args = parser.parse_args()

    if args.http:
        mcp.run(transport="streamable-http", host=args.host, port=args.port, stateless_http=args.stateless)
    else:
        mcp.run()
'''


@dataclass
class Feature:
    description: str
    snippet: Optional[str] = None
    """Inserted before ``def main()`` (tools, resources, prompts)."""
    pre_snippet: Optional[str] = None
    """Inserted before the ``mcp = MCPServer(...)`` call (things the constructor references)."""
    server_kwargs: Dict[str, str] = field(default_factory=dict)
    """Keyword arguments added to the ``MCPServer(...)`` call (name -> source expression)."""
    main: Optional[str] = None
    """Replacement for the default ``def main()``."""
    deps: List[str] = field(default_factory=list)
    requires: List[str] = field(default_factory=list)
    generator: Optional[Callable[[Path], List[Path]]] = None
    """Writes project files (distribution features); returns created paths."""
    kind: str = "protocol"


FEATURES: Dict[str, Feature] = {
    # Protocol features
    "resources": Feature(
        snippet="resources.py.snippet",
        description="Resource endpoint example",
    ),
    "resource-templates": Feature(
        snippet="resource_templates.py.snippet",
        description="Parameterised resource URIs (users://{user_id}/profile)",
    ),
    "prompts": Feature(
        snippet="prompts.py.snippet",
        description="Prompt template example",
    ),
    "completions": Feature(
        snippet="completions.py.snippet",
        description="Argument autocompletion for prompts and resource templates",
    ),
    "annotations": Feature(
        snippet="annotations.py.snippet",
        description="Tool titles and behaviour hints (read-only, destructive, idempotent)",
    ),
    "structured-output": Feature(
        snippet="structured_output.py.snippet",
        deps=["pydantic>=2.0.0"],
        description="Typed tool results with outputSchema and structuredContent",
    ),
    "media": Feature(
        snippet="media.py.snippet",
        description="Image content and resource links in tool results",
    ),
    "context": Feature(
        snippet="context.py.snippet",
        description="Progress reporting and logging via the request context",
    ),
    "elicitation": Feature(
        snippet="elicitation.py.snippet",
        deps=["pydantic>=2.0.0"],
        description="Ask the user for structured input mid-tool (Resolve + Elicit)",
    ),
    "sampling": Feature(
        snippet="sampling.py.snippet",
        description="Ask the client's LLM to generate text (Resolve + Sample)",
    ),
    "roots": Feature(
        snippet="roots.py.snippet",
        description="Read the client's workspace roots (Resolve + ListRoots)",
    ),
    "lifespan": Feature(
        pre_snippet="lifespan.py.snippet",
        snippet="lifespan_tools.py.snippet",
        server_kwargs={"lifespan": "app_lifespan"},
        description="Startup/shutdown resources shared with every request",
    ),
    "http": Feature(
        snippet="http.py.snippet",
        main=HTTP_MAIN,
        description="Streamable HTTP transport (--http) with a /health route",
    ),
    "auth": Feature(
        pre_snippet="auth.py.snippet",
        server_kwargs={
            "token_verifier": "EnvTokenVerifier()",
            "auth": (
                "AuthSettings(\n"
                "        issuer_url=AUTH_ISSUER_URL,\n"
                "        resource_server_url=RESOURCE_SERVER_URL,\n"
                '        required_scopes=["mcp:tools"],\n'
                "        validate_token_resource=True,\n"
                "    )"
            ),
        },
        requires=["http"],
        description="OAuth 2.1 resource server with a token verifier",
    ),
    "apps": Feature(
        pre_snippet="apps.py.snippet",
        server_kwargs={"extensions": "[apps]"},
        description="MCP Apps: interactive ui:// HTML views bound to tools",
    ),
    # Distribution features
    "skill": Feature(
        generator=distribute.write_skill,
        kind="distribution",
        description="Agent Skill (skills/<name>/SKILL.md) teaching Claude to use this server",
    ),
    "plugin": Feature(
        generator=distribute.write_plugin,
        requires=["skill"],
        kind="distribution",
        description="Claude Code plugin + marketplace bundling this server and its skill",
    ),
    "mcpb": Feature(
        generator=distribute.write_mcpb,
        kind="distribution",
        description="MCP Bundle manifest.json for one-click Claude Desktop install",
    ),
    "registry": Feature(
        generator=distribute.write_registry,
        kind="distribution",
        description="server.json for publishing to the official MCP Registry",
    ),
}


@dataclass
class AddResult:
    added: List[str] = field(default_factory=list)
    """Features applied by this call (including required features)."""
    skipped: List[str] = field(default_factory=list)
    """Features that were already present."""
    files: List[Path] = field(default_factory=list)
    """Files created by distribution features."""


def list_features() -> Dict[str, Feature]:
    """Return all available features."""
    return dict(FEATURES)


def _read_project_name(project_dir: Path) -> str:
    """Extract project name from pyproject.toml."""
    pyproject = project_dir / "pyproject.toml"
    if pyproject.exists():
        match = re.search(r'^name\s*=\s*"([^"]+)"', pyproject.read_text(), re.MULTILINE)
        if match:
            return match.group(1)
    return "my-server"


def _add_deps(project_dir: Path, deps: List[str]) -> None:
    """Add dependencies to pyproject.toml if not already present."""
    if not deps:
        return

    pyproject = project_dir / "pyproject.toml"
    if not pyproject.exists():
        return

    content = pyproject.read_text()
    lines = content.split("\n")

    for dep in deps:
        # Extract bare package name for substring check
        pkg_name = re.split(r"[><=!~\[]", dep)[0].strip()
        if pkg_name in content:
            continue

        # Find the dependencies array and insert before its closing ]
        in_deps = False
        for i, line in enumerate(lines):
            if re.match(r'^dependencies\s*=\s*\[', line):
                in_deps = True
            if in_deps and line.strip() == "]":
                lines.insert(i, f'    "{dep}",')
                break

    pyproject.write_text("\n".join(lines))


def _marker(feature_name: str) -> str:
    return f"# --- mcp-forge:{feature_name} ---"


def _is_applied(feature_name: str, feature: Feature, content: str) -> bool:
    if feature.generator is not None:
        return False  # generators skip existing files themselves
    return _marker(feature_name) in content


def _read_snippet(name: str, project_name: str) -> str:
    return (SNIPPETS / name).read_text().replace("{{name}}", project_name)


def _insert_before_main(content: str, snippet_text: str) -> str:
    """Insert before def main() if it exists, otherwise before if __name__, otherwise append."""
    if MAIN_MARKER in content:
        return content.replace(
            MAIN_MARKER,
            "\n" + snippet_text.rstrip("\n") + "\n" + MAIN_MARKER,
            1,
        )
    if NAME_MARKER in content:
        return content.replace(
            NAME_MARKER,
            snippet_text.rstrip("\n") + "\n\n\n" + NAME_MARKER,
            1,
        )
    return content.rstrip("\n") + "\n\n" + snippet_text


def _insert_before_server(content: str, snippet_text: str) -> str:
    """Insert before the ``mcp = MCPServer(...)`` line."""
    match = SERVER_CALL.search(content)
    if not match:
        raise ValueError("Could not find `mcp = MCPServer(...)` in server.py")
    start = match.start()
    return content[:start] + snippet_text.strip("\n") + "\n\n\n" + content[start:]


def _add_server_kwargs(content: str, kwargs: Dict[str, str]) -> str:
    """Add keyword arguments to the ``mcp = MCPServer(...)`` call, one per line.

    Existing keywords are kept as-is.
    """
    if not kwargs:
        return content
    match = SERVER_CALL.search(content)
    if not match:
        raise ValueError("Could not find `mcp = MCPServer(...)` in server.py")

    tree = ast.parse(content)
    call_line = content.count("\n", 0, match.start()) + 1
    call = next(
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign) and node.lineno == call_line and isinstance(node.value, ast.Call)
    )

    args = [ast.get_source_segment(content, arg) for arg in call.args]
    existing = {kw.arg for kw in call.keywords}
    args += [f"{kw.arg}={ast.get_source_segment(content, kw.value)}" for kw in call.keywords]
    args += [f"{key}={value}" for key, value in kwargs.items() if key not in existing]

    lines = content.split("\n")
    start = sum(len(line) + 1 for line in lines[: call.lineno - 1]) + call.col_offset
    end = sum(len(line) + 1 for line in lines[: call.end_lineno - 1]) + call.end_col_offset
    func = ast.get_source_segment(content, call.func)
    rendered = func + "(\n" + "".join(f"    {arg},\n" for arg in args) + ")"
    return content[:start] + rendered + content[end:]


def _replace_main(content: str, main: str) -> str:
    if DEFAULT_MAIN in content:
        return content.replace(DEFAULT_MAIN, main, 1)
    if MAIN_MARKER not in content:
        return _insert_before_main(content, main) if NAME_MARKER in content else content + "\n\n" + main
    # main() was customised; leave it to the user
    return content


def add_feature(feature_name: str, project_dir: Path) -> AddResult:
    """Add a feature (and the features it requires) to an MCP server project.

    Protocol features insert snippets into server.py and add dependencies to
    pyproject.toml. Distribution features write new project files. Adding a
    feature that is already present is a no-op.

    Raises:
        ValueError: If feature_name is unknown.
        FileNotFoundError: If server.py doesn't exist.
    """
    if feature_name not in FEATURES:
        raise ValueError(
            f"Unknown feature: {feature_name!r}. "
            f"Available: {', '.join(FEATURES)}"
        )

    server_py = project_dir / "server.py"
    if not server_py.exists():
        raise FileNotFoundError(f"server.py not found in {project_dir}")

    result = AddResult()
    _apply(feature_name, project_dir, result)
    return result


def _apply(feature_name: str, project_dir: Path, result: AddResult) -> None:
    feature = FEATURES[feature_name]
    for required in feature.requires:
        if required not in result.added and required not in result.skipped:
            _apply(required, project_dir, result)

    server_py = project_dir / "server.py"
    content = server_py.read_text()
    if _is_applied(feature_name, feature, content):
        result.skipped.append(feature_name)
        return

    if feature.generator is not None:
        created = feature.generator(project_dir)
        result.files.extend(created)
        (result.added if created else result.skipped).append(feature_name)
        return

    project_name = _read_project_name(project_dir)
    if feature.pre_snippet:
        content = _insert_before_server(content, _read_snippet(feature.pre_snippet, project_name))
    content = _add_server_kwargs(content, feature.server_kwargs)
    if feature.snippet:
        content = _insert_before_main(content, _read_snippet(feature.snippet, project_name))
    if feature.main:
        content = _replace_main(content, feature.main)

    server_py.write_text(content)
    _add_deps(project_dir, feature.deps)
    result.added.append(feature_name)
