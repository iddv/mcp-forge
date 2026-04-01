"""MCP-Forge CLI — scaffold MCP server projects."""

from pathlib import Path

import typer
from rich import print as rprint
from rich.panel import Panel

from mcp_forge import __version__
from mcp_forge.add import add_feature, list_features
from mcp_forge.scaffold import scaffold_project, validate_name
from mcp_forge.install import detect_clients, get_server_entry, install_in_client

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
        help="Comma-separated features to add (resources,prompts,elicitation,context,auth).",
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
        features = list_features()
        for feature_name in with_features.split(","):
            feature_name = feature_name.strip()
            if feature_name not in features:
                rprint(f"[yellow]Unknown feature:[/yellow] {feature_name}")
                rprint(f"Available: {', '.join(features)}")
                continue
            add_feature(feature_name, project_dir)
            added.append(feature_name)

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
            rprint(f"Available clients: claude, cursor, windsurf, claude-code")
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


@app.command()
def add(
    feature: str = typer.Argument(
        help="Feature to add (resources, prompts, elicitation, context, auth).",
    ),
):
    """Add an MCP feature to the current server project."""
    project_dir = Path.cwd()

    if not (project_dir / "server.py").exists():
        rprint("[red]No server.py found in current directory.[/red]")
        rprint("Run this command from an MCP server project directory.")
        raise typer.Exit(1)

    features = list_features()
    if feature not in features:
        rprint(f"[red]Unknown feature:[/red] {feature}")
        rprint(f"Available: {', '.join(features)}")
        raise typer.Exit(1)

    add_feature(feature, project_dir)
    feat = features[feature]
    rprint(f"[green]✓[/green] Added [bold]{feature}[/bold] — {feat.description}")
    if feat.deps:
        rprint(f"  [dim]Added dependencies: {', '.join(feat.deps)}[/dim]")
