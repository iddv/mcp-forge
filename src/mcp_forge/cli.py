"""MCP-Forge CLI — scaffold MCP server projects."""

import json
from pathlib import Path
from typing import List

import typer
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

from mcp_forge import __version__
from mcp_forge.add import add_feature, list_features
from mcp_forge.scaffold import scaffold_project, validate_name
from mcp_forge.install import (
    ConfigError,
    detect_clients,
    get_server_entry,
    install_in_client,
    list_clients,
)

app = typer.Typer(
    name="mcp-forge",
    help="Scaffold MCP server projects with sane defaults.",
    no_args_is_help=True,
)


def version_callback(value: bool):
    if value:
        rprint(f"mcp-forge {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-v", help="Show version and exit.",
        callback=version_callback, is_eager=True,
    ),
):
    pass


@app.command()
def new(
    name: str = typer.Argument(help="Name for the new MCP server project."),
    description: str = typer.Option(
        "An MCP server", "--description", "-d",
        help="Server description.",
    ),
    with_features: str = typer.Option(
        None, "--with",
        help="Comma-separated features to add (run `mcp-forge features` to list them).",
    ),
):
    """Create a new MCP server project."""
    if not validate_name(name):
        rprint(f"[red]Invalid project name:[/red] {name!r}")
        rprint("Use only letters, numbers, hyphens, and underscores.")
        raise typer.Exit(1)

    target = Path.cwd()
    if (target / name).exists():
        rprint(f"[red]Directory already exists:[/red] {target / name}")
        rprint("Pick a different name or remove the existing directory.")
        raise typer.Exit(1)

    names = [n.strip() for n in (with_features or "").split(",") if n.strip()]
    unknown = [n for n in names if n not in list_features()]
    if unknown:
        rprint(f"[red]Unknown feature:[/red] {', '.join(unknown)}")
        rprint(f"Available: {', '.join(list_features())}")
        raise typer.Exit(1)

    project_dir = scaffold_project(name, str(target), description=description)
    added = _apply_features(names, project_dir) if names else []

    summary = (
        f"[green]Created MCP server project:[/green] [bold]{name}[/bold]\n\n"
        f"  cd {name}\n"
        f"  mcp dev server.py    [dim]# Run with MCP Inspector[/dim]\n"
        f"  mcp-forge install    [dim]# Register in MCP clients[/dim]"
    )
    if added:
        summary += f"\n\n  [dim]Added features: {', '.join(added)}[/dim]"

    rprint(Panel.fit(summary, title="mcp-forge"))


@app.command()
def install(
    client: str = typer.Option(
        None, "--client", "-c",
        help=f"Target one client: {', '.join(list_clients())}.",
    ),
    name: str = typer.Option(
        None, "--name",
        help="Override the server name in config.",
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Overwrite existing entries without prompting.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Show what would be written, without changing any file.",
    ),
):
    """Register this MCP server in client app configurations."""
    project_dir = Path.cwd()
    server_name = name or project_dir.name

    # Check that server.py exists
    if not (project_dir / "server.py").exists():
        rprint("[red]No server.py found in current directory.[/red]")
        rprint("Run this command from an MCP server project directory.")
        raise typer.Exit(1)

    entry = get_server_entry(server_name, project_dir.resolve())
    if entry["command"] == "python3":
        rprint(
            "[yellow]uv not found and the project has no .venv.[/yellow] Clients will run "
            "`python3 server.py`, which needs `mcp` installed for that Python. Install uv, "
            "or run `python3 -m venv .venv && .venv/bin/pip install -e .` here, then re-run "
            "with --force."
        )

    # Detect clients
    if client:
        clients = detect_clients(specific=client)
        if not clients:
            rprint(f"[red]Client not found:[/red] {client}")
            rprint(f"Available clients: {', '.join(list_clients())}")
            raise typer.Exit(1)
    else:
        clients = detect_clients()
        if not clients:
            rprint("[yellow]No MCP clients detected.[/yellow]")
            rprint("Use --client to specify one manually.")
            raise typer.Exit(1)

    installed = []
    skipped = []
    failed = []
    for client_obj in clients.values():
        try:
            if install_in_client(client_obj, server_name, entry, force=force, dry_run=dry_run):
                installed.append(client_obj)
            else:
                skipped.append(client_obj)
        except (ConfigError, OSError) as exc:
            failed.append((client_obj, exc))

    if dry_run:
        rprint(f"[bold]Dry run.[/bold] Entry for '{server_name}':")
        rprint(json.dumps(entry, indent=2))
    if installed:
        verb = "Would install" if dry_run else "Installed"
        rprint(f"\n[green]{verb} '{server_name}' in:[/green]")
        for c in installed:
            rprint(f"  [green]✓[/green] {c.name}  [dim]{c.config_path}[/dim]")
    if skipped:
        rprint("\n[yellow]Skipped (already exists, use --force to overwrite):[/yellow]")
        for c in skipped:
            rprint(f"  [yellow]–[/yellow] {c.name}")
    if failed:
        rprint("\n[red]Could not update:[/red]")
        for c, exc in failed:
            rprint(f"  [red]✗[/red] {c.name}: {exc}")
        if not dry_run:
            rprint(f"\nEntry to add under \"{failed[0][0].config_key}\" by hand:")
            rprint(json.dumps({server_name: entry}, indent=2))
        raise typer.Exit(1)


def _apply_features(names: List[str], project_dir: Path) -> List[str]:
    """Add features, printing what happened. Returns the features that were added."""
    features = list_features()
    if "mcp.server.fastmcp" in (project_dir / "server.py").read_text():
        rprint(
            "[yellow]server.py uses FastMCP (mcp 1.x).[/yellow] Snippets target mcp 2.x — "
            "see https://py.sdk.modelcontextprotocol.io/v2/migration/"
        )

    added: List[str] = []
    for feature_name in names:
        if feature_name not in features:
            rprint(f"[red]Unknown feature:[/red] {feature_name}")
            rprint(f"Available: {', '.join(features)}")
            continue
        result = add_feature(feature_name, project_dir)
        for name in result.added:
            feat = features[name]
            rprint(f"[green]✓[/green] Added [bold]{name}[/bold] — {feat.description}")
            if feat.deps:
                rprint(f"  [dim]Added dependencies: {', '.join(feat.deps)}[/dim]")
        for path in result.files:
            rprint(f"  [dim]Created {path.relative_to(project_dir)}[/dim]")
        for warning in result.warnings:
            rprint(f"[yellow]![/yellow] {warning}")
        if feature_name in result.skipped:
            rprint(f"[yellow]–[/yellow] [bold]{feature_name}[/bold] is already in this project")
        added += result.added
    return added


@app.command()
def add(
    features: List[str] = typer.Argument(
        help="Features to add (run `mcp-forge features` to list them).",
    ),
):
    """Add MCP features to the current server project."""
    project_dir = Path.cwd()

    if not (project_dir / "server.py").exists():
        rprint("[red]No server.py found in current directory.[/red]")
        rprint("Run this command from an MCP server project directory.")
        raise typer.Exit(1)

    unknown = [name for name in features if name not in list_features()]
    if unknown:
        rprint(f"[red]Unknown feature:[/red] {', '.join(unknown)}")
        rprint(f"Available: {', '.join(list_features())}")
        raise typer.Exit(1)

    _apply_features(features, project_dir)


@app.command(name="features")
def features_command():
    """List the features available to `mcp-forge add`."""
    table = Table(box=None, pad_edge=False)
    table.add_column("Feature", style="bold")
    table.add_column("Kind", style="dim")
    table.add_column("What it adds")
    for name, feat in list_features().items():
        table.add_row(name, feat.kind, feat.description)
    rprint(table)
