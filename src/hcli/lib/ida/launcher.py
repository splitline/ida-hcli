"""IDA launcher with robust startup handling.

This module provides functionality to launch IDA with an IDB file
and wait for it to become ready via IPC.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from hcli.lib.config import config_store
from hcli.lib.ida import (
    find_current_ida_install_directory,
    get_ida_binary_path,
    MissingCurrentInstallationDirectory,
)
from hcli.lib.ida.ipc import IDAIPCClient, IDAInstance

logger = logging.getLogger(__name__)


class IDALaunchError(Exception):
    """Failed to launch IDA process."""

    def __init__(self, message: str, exit_code: int | None = None):
        self.exit_code = exit_code
        super().__init__(message)


class IDAStartupTimeout(Exception):
    """IDA took too long to become responsive."""

    def __init__(self, timeout: float, phase: str):
        self.timeout = timeout
        self.phase = phase
        super().__init__(f"IDA startup timeout after {timeout}s during {phase}")


class IDBNotFoundError(Exception):
    """IDB file not found in search paths."""

    def __init__(self, idb_filename: str, search_paths: list[str]):
        self.idb_filename = idb_filename
        self.search_paths = search_paths
        super().__init__(f"IDB '{idb_filename}' not found in search paths")


class NoIDAInstallationError(Exception):
    """No IDA installation configured or found."""

    pass


@dataclass
class LaunchConfig:
    """Configuration for IDA launch behavior."""

    socket_timeout: float = 30.0
    idb_loaded_timeout: float = 90.0
    initial_poll_interval: float = 0.1
    max_poll_interval: float = 2.0
    backoff_multiplier: float = 1.5
    skip_analysis_wait: bool = False
    analysis_poll_interval: float = 5.0  # seconds between analysis polls


@dataclass
class LaunchResult:
    """Result of an IDA launch attempt."""

    success: bool
    instance: IDAInstance | None = None
    process: subprocess.Popen | None = None
    error_message: str | None = None


class IDALauncher:
    """Manages IDA process lifecycle with robust error handling."""

    SOCKET_PREFIX = "ida_ipc_"

    def __init__(self, config: LaunchConfig | None = None):
        self.config = config or LaunchConfig()

    def find_idb_file(self, idb_filename: str) -> Path | None:
        """Search idb.search-paths for the IDB file.

        Args:
            idb_filename: The IDB filename to search for (e.g., "test.idb", "sample.i64")

        Returns:
            Full path to the IDB file if found, None otherwise.
        """
        search_paths: list[str] = config_store.get_object("idb.search-paths", []) or []

        if not search_paths:
            logger.debug("No IDB search paths configured")
            return None

        for dir_path in search_paths:
            dir_path_obj = Path(dir_path)
            if not dir_path_obj.exists():
                logger.debug(f"Search path does not exist: {dir_path}")
                continue

            # Search recursively for matching filename
            for idb_path in dir_path_obj.rglob(idb_filename):
                if idb_path.is_file():
                    logger.debug(f"Found IDB: {idb_path}")
                    return idb_path

        logger.debug(f"IDB '{idb_filename}' not found in any search path")
        return None

    def get_ida_binary(self) -> Path:
        """Get IDA binary from ida.default/ida.instances config.

        Returns:
            Path to the IDA binary.

        Raises:
            NoIDAInstallationError: If no IDA installation is configured or found.
        """
        # Try ida.instances configuration first
        default_instance = config_store.get_string("ida.default", "")
        instances: dict[str, str] = config_store.get_object("ida.instances", {}) or {}

        if default_instance and default_instance in instances:
            ida_dir = Path(instances[default_instance])
            ida_bin = get_ida_binary_path(ida_dir)
            if ida_bin.exists():
                logger.debug(f"Using configured IDA: {ida_bin}")
                return ida_bin
            else:
                logger.warning(f"Configured IDA binary not found: {ida_bin}")

        # Fallback to standard discovery
        try:
            ida_dir = find_current_ida_install_directory()
            ida_bin = get_ida_binary_path(ida_dir)
            if ida_bin.exists():
                logger.debug(f"Using discovered IDA: {ida_bin}")
                return ida_bin
        except MissingCurrentInstallationDirectory:
            pass

        raise NoIDAInstallationError(
            "No IDA installation configured. Use: hcli ida instance add --auto"
        )

    def launch_and_wait(
        self,
        idb_path: Path,
        timeout: float | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> LaunchResult:
        """Launch IDA with an IDB file and wait for it to be ready.

        Args:
            idb_path: Full path to the IDB file.
            timeout: Total timeout in seconds (default: socket_timeout + idb_loaded_timeout).
            progress_callback: Optional callback for progress messages.

        Returns:
            LaunchResult with success status and instance info.
        """

        def report(msg: str) -> None:
            if progress_callback:
                progress_callback(msg)
            logger.info(msg)

        # Validate IDB file exists
        if not idb_path.exists():
            return LaunchResult(
                success=False, error_message=f"IDB file not found: {idb_path}"
            )

        if not idb_path.is_file():
            return LaunchResult(
                success=False, error_message=f"IDB path is not a file: {idb_path}"
            )

        # Get IDA binary
        try:
            ida_bin = self.get_ida_binary()
        except NoIDAInstallationError as e:
            return LaunchResult(success=False, error_message=str(e))

        # Launch IDA process
        report(f"Launching IDA: {ida_bin.name}")
        try:
            process = subprocess.Popen(
                [str(ida_bin), str(idb_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,  # Detach from parent
            )
        except OSError as e:
            return LaunchResult(success=False, error_message=f"Failed to start IDA: {e}")

        pid = process.pid
        socket_path = self._get_expected_socket_path(pid)

        # Calculate timeouts
        socket_timeout = self.config.socket_timeout
        idb_timeout = self.config.idb_loaded_timeout
        if timeout is not None:
            # Distribute timeout between phases
            socket_timeout = min(self.config.socket_timeout, timeout * 0.3)
            idb_timeout = min(self.config.idb_loaded_timeout, timeout * 0.7)

        # Wait for socket to become responsive
        report(f"Waiting for IDA (PID {pid}) to initialize...")
        try:
            self._wait_for_socket_responsive(process, socket_path, socket_timeout)
        except IDALaunchError as e:
            return LaunchResult(success=False, process=process, error_message=str(e))
        except IDAStartupTimeout as e:
            return LaunchResult(success=False, process=process, error_message=str(e))

        # Wait for IDB to be loaded
        report("Waiting for IDB to load...")
        try:
            instance = self._wait_for_idb_loaded(process, socket_path, idb_timeout)
        except IDALaunchError as e:
            return LaunchResult(success=False, process=process, error_message=str(e))
        except IDAStartupTimeout as e:
            return LaunchResult(success=False, process=process, error_message=str(e))

        # Wait for auto-analysis to complete (unless skipped)
        if not self.config.skip_analysis_wait:
            report("Waiting for auto-analysis to complete (Ctrl+C to skip)...")
            try:
                self._wait_for_analysis(process, socket_path, report)
            except IDALaunchError as e:
                return LaunchResult(success=False, process=process, error_message=str(e))
            except KeyboardInterrupt:
                report("Analysis wait cancelled by user")

        report("IDA is ready!")
        return LaunchResult(success=True, instance=instance, process=process)

    def _get_expected_socket_path(self, pid: int) -> str:
        """Get expected IPC socket/pipe path for a PID."""
        if sys.platform == "win32":
            return f"\\\\.\\pipe\\{self.SOCKET_PREFIX}{pid}"
        else:
            return f"/tmp/{self.SOCKET_PREFIX}{pid}"

    def _socket_exists(self, socket_path: str) -> bool:
        """Check if socket/pipe exists."""
        if sys.platform == "win32":
            return self._windows_pipe_exists(socket_path)
        else:
            return Path(socket_path).exists()

    def _windows_pipe_exists(self, pipe_path: str) -> bool:
        """Check if Windows named pipe exists."""
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateFileW(
                pipe_path,
                0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
                0,
                None,
                3,  # OPEN_EXISTING
                0,
                None,
            )
            if handle != -1:
                kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False

    def _wait_for_socket_responsive(
        self, process: subprocess.Popen, socket_path: str, timeout: float
    ) -> None:
        """Wait for socket to exist and respond to ping."""
        start = time.monotonic()
        interval = self.config.initial_poll_interval

        while time.monotonic() - start < timeout:
            # Check process health
            exit_code = process.poll()
            if exit_code is not None:
                raise IDALaunchError(
                    f"IDA exited unexpectedly with code {exit_code}", exit_code=exit_code
                )

            # Check if socket exists and responds to ping
            if self._socket_exists(socket_path) and IDAIPCClient.ping(socket_path):
                return

            time.sleep(interval)
            interval = min(
                interval * self.config.backoff_multiplier, self.config.max_poll_interval
            )

        raise IDAStartupTimeout(timeout, "socket_responsive")

    def _wait_for_idb_loaded(
        self, process: subprocess.Popen, socket_path: str, timeout: float
    ) -> IDAInstance:
        """Wait for IDB to be loaded and return instance info."""
        start = time.monotonic()
        interval = self.config.initial_poll_interval

        while time.monotonic() - start < timeout:
            # Check process health
            exit_code = process.poll()
            if exit_code is not None:
                raise IDALaunchError(
                    f"IDA exited unexpectedly with code {exit_code}", exit_code=exit_code
                )

            # Query instance for IDB info
            info = IDAIPCClient.query_instance(socket_path)
            if info and info.has_idb:
                return info

            time.sleep(interval)
            interval = min(
                interval * self.config.backoff_multiplier, self.config.max_poll_interval
            )

        raise IDAStartupTimeout(timeout, "idb_loaded")

    def _wait_for_analysis(
        self,
        process: subprocess.Popen,
        socket_path: str,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        """Wait for auto-analysis to complete with cancel support.

        Uses IDA's native auto_wait() via timeout_ms=0, with periodic
        process health checks. User can cancel with Ctrl+C.
        """
        poll_ms = int(self.config.analysis_poll_interval * 1000)
        start = time.monotonic()

        while True:
            # Check process health
            exit_code = process.poll()
            if exit_code is not None:
                raise IDALaunchError(
                    f"IDA exited unexpectedly with code {exit_code}", exit_code=exit_code
                )

            # Use short timeout to allow Ctrl+C and process health checks
            result = IDAIPCClient.wait_for_analysis(socket_path, timeout_ms=poll_ms)

            if result.success:
                elapsed = time.monotonic() - start
                if progress_callback:
                    progress_callback(f"Analysis complete ({elapsed:.1f}s)")
                return

            if result.status == "cancelled":
                raise IDALaunchError("Analysis cancelled by user in IDA")

            if result.status == "timeout":
                # Analysis still in progress, print progress and continue
                elapsed = time.monotonic() - start
                if progress_callback:
                    progress_callback(f"Waiting for analysis... ({elapsed:.0f}s)")
                continue

            # Error status
            raise IDALaunchError(f"Analysis error: {result.message}")
