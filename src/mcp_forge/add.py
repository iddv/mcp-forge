"""Add MCP features to an existing server project."""

import re
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Dict, List


SNIPPETS = files("mcp_forge") / "snippets"


@dataclass
class Feature:
    snippet: str
    deps: List[str] = field(default_factory=list)
    description: str = ""


FEATURES: Dict[str, Feature] = {
    "resources": Feature(
        snippet="resources.py.snippet",
        deps=[],
        description="Resource endpoint example",
    ),
    "prompts": Feature(
        snippet="prompts.py.snippet",
        deps=[],
        description="Prompt template example",
    ),
    "elicitation": Feature(
        snippet="elicitation.py.snippet",
        deps=["pydantic>=2.0.0"],
        description="User input elicitation example",
    ),
    "context": Feature(
        snippet="context.py.snippet",
        deps=[],
        description="Context logging and progress example",
    ),
    "auth": Feature(
        snippet="auth.py.snippet",
        deps=[],
        description="OAuth 2.0 auth configuration",
    ),
}


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


def add_feature(feature_name: str, project_dir: Path) -> None:
    """Add a feature to an existing MCP server project.

    Reads the snippet file, inserts it into server.py before
    ``if __name__ == "__main__":`` (or appends), and adds any
    required dependencies to pyproject.toml.

    Raises:
        ValueError: If feature_name is unknown.
        FileNotFoundError: If server.py doesn't exist.
    """
    if feature_name not in FEATURES:
        raise ValueError(
            f"Unknown feature: {feature_name!r}. "
            f"Available: {', '.join(FEATURES)}"
        )

    feature = FEATURES[feature_name]
    server_py = project_dir / "server.py"

    if not server_py.exists():
        raise FileNotFoundError(f"server.py not found in {project_dir}")

    # Read snippet and replace placeholders
    snippet_text = (SNIPPETS / feature.snippet).read_text()
    project_name = _read_project_name(project_dir)
    snippet_text = snippet_text.replace("{{name}}", project_name)

    # Insert into server.py — before def main() if it exists,
    # otherwise before if __name__, otherwise append
    content = server_py.read_text()
    main_marker = "\ndef main():"
    name_marker = 'if __name__ == "__main__":'

    if main_marker in content:
        content = content.replace(
            main_marker,
            "\n" + snippet_text.rstrip("\n") + "\n" + main_marker,
        )
    elif name_marker in content:
        content = content.replace(
            name_marker,
            snippet_text.rstrip("\n") + "\n\n\n" + name_marker,
        )
    else:
        content = content.rstrip("\n") + "\n\n" + snippet_text

    server_py.write_text(content)

    # Add dependencies
    _add_deps(project_dir, feature.deps)
