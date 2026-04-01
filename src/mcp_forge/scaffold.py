"""Scaffold new MCP server projects from templates."""

import re
from importlib.resources import files
from pathlib import Path


TEMPLATES = files("mcp_forge") / "templates"

NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")


def validate_name(name: str) -> bool:
    """Check if a project name is valid."""
    if not name:
        return False
    return bool(NAME_PATTERN.match(name))


def scaffold_project(
    name: str,
    parent_dir: str,
    description: str = "An MCP server",
) -> Path:
    """Create a new MCP server project directory with all template files.

    Args:
        name: Project name (used for directory, package name, server name).
        parent_dir: Directory to create the project in.
        description: Server description.

    Returns:
        Path to the created project directory.

    Raises:
        ValueError: If name is invalid.
        FileExistsError: If project directory already exists.
    """
    if not validate_name(name):
        raise ValueError(
            f"Invalid project name: {name!r}. "
            "Use only letters, numbers, hyphens, and underscores."
        )

    project_dir = Path(parent_dir) / name
    if project_dir.exists():
        raise FileExistsError(f"Directory already exists: {project_dir}")

    project_dir.mkdir(parents=True)
    (project_dir / "tests").mkdir()

    replacements = {"{{name}}": name, "{{description}}": description}

    file_map = {
        "server.py.tpl": "server.py",
        "pyproject.toml.tpl": "pyproject.toml",
        "test_server.py.tpl": "tests/test_server.py",
        "env.example.tpl": ".env.example",
        "gitignore.tpl": ".gitignore",
        "readme.md.tpl": "README.md",
    }

    for template_name, output_name in file_map.items():
        template_content = (TEMPLATES / template_name).read_text()
        for placeholder, value in replacements.items():
            template_content = template_content.replace(placeholder, value)
        (project_dir / output_name).write_text(template_content)

    return project_dir
