from __future__ import annotations

import rich_click as click


@click.group()
def idb() -> None:
    """IDB file management commands."""
    pass


from .search_path import search_path  # noqa: E402

idb.add_command(search_path, name="search-path")
