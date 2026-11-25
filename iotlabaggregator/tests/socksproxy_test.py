# This file is a part of IoT-LAB aggregation-tools
# Copyright (C) 2026 INRIA (Contact: admin@iot-lab.info)
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

"""Tests for iotlabaggregator.socksproxy"""

import os
import socket
import stat
import struct
import sys
import tempfile
import textwrap
import threading
import unittest
from unittest.mock import Mock, patch

from iotlabaggregator import common, connections, socksproxy


class FakeSocks5Server:
    """SOCKS5 server answering one CONNECT per client, then echoing.

    Records the requested (host, port); ``reply`` is the SOCKS reply code.
    """

    def __init__(self, reply=0):
        self.reply = reply
        self.requests = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.address = self.sock.getsockname()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._client, args=(client,), daemon=True).start()

    def _client(self, client):
        with client:
            client.recv(3)  # version, 1 method, no auth
            client.sendall(b"\x05\x00")
            header = client.recv(5)  # version, connect, rsv, domain, length
            name = client.recv(header[4]).decode()
            (port,) = struct.unpack("!H", client.recv(2))
            self.requests.append((name, port))
            client.sendall(bytes([5, self.reply, 0, 1]) + b"\x7f\x00\x00\x01\x00\x00")
            if self.reply:
                return
            while True:
                data = client.recv(1024)
                if not data:
                    return
                client.sendall(data)

    def close(self):
        self.sock.close()


class TestSocks5Connect(unittest.TestCase):
    """socks5_connect against a fake server."""

    def test_connect_by_name_and_echo(self):
        server = FakeSocks5Server()
        try:
            sock = socksproxy.socks5_connect(server.address, "m3-1", 20000)
            with sock:
                sock.sendall(b"hello\n")
                self.assertEqual(b"hello\n", sock.recv(16))
            self.assertEqual([("m3-1", 20000)], server.requests)
        finally:
            server.close()

    def test_refused(self):
        server = FakeSocks5Server(reply=5)
        try:
            with self.assertRaisesRegex(
                socksproxy.SocksError, "m3-1:20000: connection refused"
            ):
                socksproxy.socks5_connect(server.address, "m3-1", 20000)
        finally:
            server.close()

    def test_no_proxy(self):
        port = socksproxy.free_local_port()
        with self.assertRaises(OSError):
            socksproxy.socks5_connect(("127.0.0.1", port), "m3-1", 20000)


class TestFreeLocalPort(unittest.TestCase):
    def test_bindable(self):
        port = socksproxy.free_local_port()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", port))


# a fake ssh: listens on the -D port, or fails like a refused login
FAKE_SSH = textwrap.dedent(
    """\
    #!{python}
    import socket, sys, time
    if "{mode}" == "fail":
        sys.stderr.write("Permission denied (publickey).\\n")
        sys.exit(255)
    port = int(sys.argv[sys.argv.index("-D") + 1].rsplit(":", 1)[1])
    sock = socket.socket()
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    while True:
        time.sleep(1)
    """
)


class TestSshSocksProxy(unittest.TestCase):
    """SshSocksProxy with a fake ssh command."""

    def _fake_ssh(self, mode):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        with tmp:
            tmp.write(FAKE_SSH.format(python=sys.executable, mode=mode))
        os.chmod(tmp.name, os.stat(tmp.name).st_mode | stat.S_IXUSR)
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def test_command(self):
        proxy = socksproxy.SshSocksProxy("grenoble", "login")
        cmd = proxy.command(1080)
        self.assertEqual(["ssh", "-N", "-D", "127.0.0.1:1080"], cmd[:4])
        self.assertIn("ExitOnForwardFailure=yes", cmd)
        self.assertEqual("login@grenoble.iot-lab.info", cmd[-1])

    def test_start_stop(self):
        proxy = socksproxy.SshSocksProxy("grenoble", "login", ssh=self._fake_ssh("ok"))
        proxy.start()
        try:
            host, port = proxy.address
            with socket.create_connection((host, port), timeout=2):
                pass
        finally:
            proxy.stop()
        self.assertIsNone(proxy.port)

    def test_start_fails(self):
        proxy = socksproxy.SshSocksProxy(
            "grenoble", "login", ssh=self._fake_ssh("fail")
        )
        with self.assertRaisesRegex(RuntimeError, "grenoble failed: Permission denied"):
            proxy.start()

    def test_frontend_proxies_given(self):
        given = {"grenoble": ("127.0.0.1", 1080)}
        with patch.object(socksproxy, "SshSocksProxy") as cls:
            with socksproxy.frontend_proxies(["grenoble"], "login", given) as proxies:
                self.assertEqual(given, proxies)
            cls.assert_not_called()


class TestConnectionThroughProxy(unittest.TestCase):
    """Connection.start of a node named <node>.<site>."""

    def test_start_through_proxy(self):
        server = FakeSocks5Server()
        try:
            aggregator = Mock(proxies={"grenoble": server.address})
            conn = connections.Connection("m3-1.grenoble", aggregator)
            conn.start()
            conn.send(b"ping\n")
            self.assertEqual(b"ping\n", conn.recv(16))
            conn.close()
            self.assertEqual([("m3-1", 20000)], server.requests)
        finally:
            server.close()

    def test_no_proxy_for_site(self):
        conn = connections.Connection("m3-1.lille", Mock(proxies={}))
        with self.assertRaisesRegex(OSError, "no SOCKS proxy for site lille"):
            conn.start()

    def test_send_to_short_name(self):
        nodes = ["m3-1.grenoble", "m3-1.saclay", "m3-2.saclay"]
        aggregator = connections.Aggregator(nodes)
        for node in aggregator.values():
            node.send = Mock()
        aggregator.send_nodes(["m3-1"], "hi\n")
        aggregator["m3-1.grenoble"].send.assert_called_once_with(b"hi\n")
        aggregator["m3-1.saclay"].send.assert_called_once_with(b"hi\n")
        aggregator["m3-2.saclay"].send.assert_not_called()


class TestRemoteSelection(unittest.TestCase):
    """query_nodes outside a frontend."""

    RESOURCES = {
        "items": [
            {"network_address": "m3-1.grenoble.iot-lab.info", "site": "grenoble"},
            {"network_address": "m3-2.saclay.iot-lab.info", "site": "saclay"},
        ]
    }

    @patch("iotlabcli.experiment.get_experiment")
    def test_every_site(self, get_experiment):
        get_experiment.return_value = self.RESOURCES
        nodes = common.query_nodes(Mock(), 123, hostname="laptop")
        self.assertEqual(["m3-1.grenoble", "m3-2.saclay"], nodes)

    @patch("iotlabcli.experiment.get_experiment")
    def test_selected(self, get_experiment):
        get_experiment.return_value = self.RESOURCES
        nodes = common.query_nodes(
            Mock(), 123, [["m3-2.saclay.iot-lab.info"]], hostname="laptop"
        )
        self.assertEqual(["m3-2.saclay"], nodes)

    @patch("iotlabcli.experiment.get_experiment")
    def test_frontend_unchanged(self, get_experiment):
        get_experiment.return_value = self.RESOURCES
        self.assertEqual(["m3-1"], common.query_nodes(Mock(), 123, hostname="grenoble"))

    def test_nodes_proxies_frontend(self):
        with common.nodes_proxies(["m3-1", "m3-2"]) as proxies:
            self.assertEqual({}, proxies)
