"""IDA instance management commands (re-exported from ke ida)."""
from __future__ import annotations

import rich_click as click


@click.group()
def instance() -> None:
    """Manage registered IDA installations."""
    pass


# Re-export ke ida commands under this group
from hcli.commands.ke.ida.add import add  # noqa: E402
from hcli.commands.ke.ida.list import list_instances as list_cmd  # noqa: E402
from hcli.commands.ke.ida.remove import remove  # noqa: E402
from hcli.commands.ke.ida.switch import switch as set_default  # noqa: E402

instance.add_command(add)
instance.add_command(list_cmd, name="list")
instance.add_command(remove)
instance.add_command(set_default, name="set-default")
