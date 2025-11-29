"""Open idb:// links in running IDA instances."""

from __future__ import annotations

from urllib.parse import urlparse

import rich_click as click
from rich.console import Console

from hcli.lib.ida.ipc import (
    IDAIPCClient,
    find_all_instances_with_info,
    find_instance_for_idb,
)

console = Console()


@click.command(name="open-link")
@click.argument("uri", required=True)
def open_link(uri: str) -> None:
    """Open an idb:// link in the appropriate IDA instance.

    This command finds a running IDA instance that has the specified IDB open
    and sends it an open_link command to navigate to the specified location.

    Example URIs:
        idb://myfile/functions?ea=0x401000
        idb://myfile/addresses?ea=0x401000&view=disasm
        idb://myfile/types?name=MyStruct
    """
    if not uri:
        console.print("[red]Error: No URI provided[/red]")
        raise click.Abort()

    # Parse URL to extract IDB name
    parsed = urlparse(uri)

    if parsed.scheme != "idb":
        console.print(f"[red]Error: Expected idb:// URL, got {parsed.scheme}://[/red]")
        raise click.Abort()

    target_idb_name = parsed.netloc  # e.g., "myfile" from idb://myfile/...

    if not target_idb_name:
        console.print("[red]Error: No IDB name in URL[/red]")
        console.print("[yellow]Expected format: idb://<idb-name>/<resource>?<params>[/yellow]")
        raise click.Abort()

    # Discover running IDA instances
    console.print(f"[dim]Looking for IDA instance with '{target_idb_name}'...[/dim]")
    instances = IDAIPCClient.discover_instances()

    if not instances:
        console.print("[yellow]No running IDA instances found.[/yellow]")
        # TODO: In future, launch IDA with the IDB
        raise click.Abort()

    # Query each instance to find one with the matching IDB
    matching_instance = None
    all_idbs = []

    for instance in instances:
        info = IDAIPCClient.query_instance(instance.socket_path)
        if info and info.has_idb:
            all_idbs.append(info.idb_name)
            if info.idb_name and info.idb_name.lower() == target_idb_name.lower():
                matching_instance = info
                break

    if not matching_instance:
        console.print(f"[yellow]No IDA instance has '{target_idb_name}' open.[/yellow]")
        if all_idbs:
            console.print("[dim]Currently open IDBs:[/dim]")
            for idb in all_idbs:
                console.print(f"  - {idb}")
        # TODO: In future, launch IDA with the IDB
        raise click.Abort()

    # Send open_link command
    console.print(f"[dim]Sending command to IDA (PID {matching_instance.pid})...[/dim]")
    success, message = IDAIPCClient.send_open_link(matching_instance.socket_path, uri)

    if success:
        console.print(f"[green]Navigated to: {uri}[/green]")
    else:
        console.print(f"[red]Error: {message}[/red]")
        raise click.Abort()


@click.command(name="list-instances")
def list_instances() -> None:
    """List all running IDA instances with IPC sockets."""
    instances = find_all_instances_with_info()

    if not instances:
        console.print("[yellow]No running IDA instances found.[/yellow]")
        return

    console.print(f"[green]Found {len(instances)} IDA instance(s):[/green]")
    for instance in instances:
        if instance.has_idb:
            console.print(f"  PID {instance.pid}: {instance.idb_name} ({instance.idb_path})")
        else:
            console.print(f"  PID {instance.pid}: [dim]no IDB loaded[/dim]")
