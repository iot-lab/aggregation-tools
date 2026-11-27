# This file is a part of IoT-LAB aggregation-tools
# Copyright (C) 2015 INRIA (Contact: admin@iot-lab.info)
# Contributor(s) : see AUTHORS file
#
# This software is governed by the CeCILL license under French law
# and abiding by the rules of distribution of free software.  You can  use,
# modify and/ or redistribute the software under the terms of the CeCILL
# license as circulated by CEA, CNRS and INRIA at the following URL
# http://www.cecill.info.
#
# As a counterpart to the access to the source code and  rights to copy,
# modify and redistribute granted by the license, users are provided only
# with a limited warranty  and the software's author,  the holder of the
# economic rights,  and the successive licensors  have only  limited
# liability.
#
# The fact that you are presently reading this means that you have had
# knowledge of the CeCILL license and that you accept its terms.

"""Reach the nodes from outside the SSH frontends, through SOCKS proxies.

The nodes ports (serial 20000, sniffer 30000) are only reachable from the
SSH frontend of their site. ``SshSocksProxy`` starts ``ssh -N -D`` to a
frontend: a local SOCKS5 proxy whose connections are opened by the
frontend. ``socks5_connect`` opens a connection to a node through it, the
node name being resolved by the frontend.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import subprocess
import time
from collections.abc import Iterator

from iotlabaggregator import LOGGER

FRONTEND_FMT = "{site}.iot-lab.info"
READY_TIMEOUT = 20.0
START_ATTEMPTS = 3

_SOCKS_VERSION = 5
_NO_AUTH = 0
_CMD_CONNECT = 1
_ATYP_DOMAIN = 3
_ATYP_IPV4 = 1
_ATYP_IPV6 = 4

_SOCKS_ERRORS = {
    1: "general SOCKS server failure",
    2: "connection not allowed by ruleset",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


class SocksError(OSError):
    """SOCKS5 negotiation or connection failure."""


def free_local_port(host: str = "127.0.0.1") -> int:
    """Return a TCP port of ``host`` that is free now.

    The port is free when this returns, another process may take it before
    it is used: callers retry on a bind failure.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise SocksError("SOCKS proxy closed the connection")
        data += chunk
    return data


def socks5_connect(
    proxy: tuple[str, int], host: str, port: int, timeout: float = 10.0
) -> socket.socket:
    """Open a TCP connection to ``host:port`` through the SOCKS5 ``proxy``.

    ``host`` is sent as a name, resolved by the proxy side (the frontend
    knows the nodes names). Returns a connected blocking socket.
    """
    sock = socket.create_connection(proxy, timeout=timeout)
    try:
        sock.sendall(bytes([_SOCKS_VERSION, 1, _NO_AUTH]))
        version, method = _recv_exact(sock, 2)
        if version != _SOCKS_VERSION or method != _NO_AUTH:
            raise SocksError(f"SOCKS proxy refused: version {version} method {method}")

        name = host.encode("idna")
        if len(name) > 255:
            raise SocksError(f"host name too long: {host!r}")
        request = bytes([_SOCKS_VERSION, _CMD_CONNECT, 0, _ATYP_DOMAIN, len(name)])
        sock.sendall(request + name + struct.pack("!H", port))

        version, reply, _, atyp = _recv_exact(sock, 4)
        if version != _SOCKS_VERSION:
            raise SocksError(f"bad SOCKS reply version {version}")
        if reply != 0:
            reason = _SOCKS_ERRORS.get(reply, f"error {reply}")
            raise SocksError(f"{host}:{port}: {reason}")
        # bound address, unused
        if atyp == _ATYP_IPV4:
            _recv_exact(sock, 4 + 2)
        elif atyp == _ATYP_IPV6:
            _recv_exact(sock, 16 + 2)
        elif atyp == _ATYP_DOMAIN:
            (length,) = _recv_exact(sock, 1)
            _recv_exact(sock, length + 2)
        else:
            raise SocksError(f"bad SOCKS address type {atyp}")
    except BaseException:
        sock.close()
        raise
    sock.settimeout(None)
    return sock


class SshSocksProxy:
    """A local SOCKS5 proxy through ``ssh -N -D`` to a site frontend.

    :param site: site name, the frontend is ``<site>.iot-lab.info``
    :param user: IoT-LAB login
    :param ssh: ssh command (tests replace it)
    """

    def __init__(self, site: str, user: str, ssh: str = "ssh") -> None:
        self.site = site
        self.user = user
        self.ssh = ssh
        self.port: int | None = None
        self._proc: subprocess.Popen | None = None

    @property
    def address(self) -> tuple[str, int]:
        """Local address of the proxy."""
        assert self.port is not None, "proxy not started"
        return ("127.0.0.1", self.port)

    def command(self, port: int) -> list[str]:
        """ssh command line of the proxy on ``port``."""
        return [
            self.ssh,
            "-N",
            "-D",
            f"127.0.0.1:{port}",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "ServerAliveInterval=30",
            f"{self.user}@{FRONTEND_FMT.format(site=self.site)}",
        ]

    def start(self) -> None:
        """Start the proxy, retrying when its port was taken meanwhile."""
        error = ""
        for _ in range(START_ATTEMPTS):
            port = free_local_port()
            self._proc = subprocess.Popen(
                self.command(port),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            if self._wait_ready(port):
                self.port = port
                LOGGER.info("SOCKS proxy to %s on port %u", self.site, port)
                return
            error = self._stderr()
            self._terminate()
        raise RuntimeError(f"SOCKS proxy to {self.site} failed: {error.strip()}")

    def _wait_ready(self, port: int) -> bool:
        deadline = time.monotonic() + READY_TIMEOUT
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                return False  # ssh exited: login refused, port taken, ...
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    return True
            except OSError:
                time.sleep(0.2)
        return False

    def _stderr(self) -> str:
        if self._proc is None or self._proc.poll() is None:
            return "no answer from the frontend"
        return self._proc.stderr.read().decode("utf-8", "replace")

    def _terminate(self) -> None:
        if self._proc is None:
            return
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        self._proc.stderr.close()
        self._proc = None

    def stop(self) -> None:
        """Stop the proxy."""
        self._terminate()
        self.port = None


def parse_socks_option(value: str) -> tuple[str, tuple[str, int]]:
    """Parse ``<site>=<host>:<port>`` of the --socks option.

    >>> parse_socks_option("grenoble=localhost:1080")
    ('grenoble', ('localhost', 1080))
    >>> parse_socks_option("grenoble")
    Traceback (most recent call last):
    ...
    ValueError: --socks expects <site>=<host>:<port>, got 'grenoble'
    """
    try:
        site, address = value.split("=", 1)
        host, port = address.rsplit(":", 1)
        return site, (host, int(port))
    except ValueError:
        raise ValueError(
            f"--socks expects <site>=<host>:<port>, got {value!r}"
        ) from None


@contextlib.contextmanager
def frontend_proxies(
    sites: list[str], user: str, given: dict[str, tuple[str, int]] | None = None
) -> Iterator[dict[str, tuple[str, int]]]:
    """Yield a SOCKS proxy address per site, started for the sites not ``given``.

    The started proxies are stopped on exit.
    """
    proxies = dict(given or {})
    started = []
    try:
        for site in sites:
            if site in proxies:
                continue
            proxy = SshSocksProxy(site, user)
            proxy.start()
            started.append(proxy)
            proxies[site] = proxy.address
        yield proxies
    finally:
        for proxy in started:
            proxy.stop()
