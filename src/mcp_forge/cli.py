"""MCP-Forge CLI — scaffold MCP server projects."""

from pathlib import Path
from typing import List

import typer
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

from mcp_forge import __version__
from mcp_forge.add import add_feature, list_features
from mcp_forge.scaffold import scaffold_project, validate_name
from mcp_forge.install import detect_clients, get_server_entry, install_in_client, list_clients

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

    project_dir = scaffold_project(name, str(target), description=description)

    # Add requested features
    added = []
    if with_features:
        names = [name.strip() for name in with_features.split(",") if name.strip()]
        added = _apply_features(names, project_dir)

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
        help="Target a specific client (claude, cursor, windsurf, claude-code).",
    ),
    name: str = typer.Option(
        None, "--name",
        help="Override the server name in config.",
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Overwrite existing entries without prompting.",
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

    # Install in each client
    installed = []
    skipped = []
    for key, client_obj in clients.items():
        result = install_in_client(client_obj, server_name, entry, force=force)
        if result:
            installed.append(client_obj.name)
        else:
            skipped.append(client_obj.name)

    # Report
    if installed:
        rprint(f"\n[green]Installed '{server_name}' in:[/green]")
        for client_name in installed:
            rprint(f"  [green]✓[/green] {client_name}")
    if skipped:
        rprint(f"\n[yellow]Skipped (already exists, use --force to overwrite):[/yellow]")
        for client_name in skipped:
            rprint(f"  [yellow]–[/yellow] {client_name}")


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
