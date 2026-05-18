#! /usr/bin/python

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

"""Tests for iotlabaggregator.connections"""

import unittest
from unittest.mock import MagicMock, Mock, patch

from iotlabaggregator import connections


class TestConnection(unittest.TestCase):
    """Tests for the Connection class."""

    def _make_conn(self):
        aggregator = Mock()
        return connections.Connection("m3-1", aggregator)

    def test_init(self):
        conn = self._make_conn()
        self.assertEqual("m3-1", conn.hostname)
        self.assertEqual("", conn.data_buff)
        self.assertIsNone(conn._sock)

    def test_handle_data_default(self):
        conn = self._make_conn()
        # Base implementation returns empty string (remaining unprocessed data)
        remaining = conn.handle_data("some data")
        self.assertEqual("", remaining)

    def test_handle_close(self):
        conn = self._make_conn()
        conn._sock = Mock()
        conn.handle_close()
        self.assertIsNone(conn._sock)
        conn.aggregator.pop.assert_called_with("m3-1", None)

    def test_close_idempotent(self):
        conn = self._make_conn()
        conn._sock = Mock()
        conn.close()
        self.assertIsNone(conn._sock)
        # Second close should not raise
        conn.close()

    def test_close_ignores_oserror(self):
        conn = self._make_conn()
        sock = Mock()
        sock.close.side_effect = OSError("already closed")
        conn._sock = sock
        conn.close()  # should not raise
        self.assertIsNone(conn._sock)

    def test_handle_read(self):
        conn = self._make_conn()
        conn.recv = Mock(return_value=b"hello\nworld\n")
        conn.handle_data = Mock(return_value="")
        conn.handle_read()
        conn.handle_data.assert_called_once_with("hello\nworld\n")

    def test_send(self):
        conn = self._make_conn()
        sock = Mock()
        conn._sock = sock
        conn.send(b"hello")
        sock.sendall.assert_called_with(b"hello")

    def test_send_no_socket(self):
        conn = self._make_conn()
        conn._sock = None
        conn.send(b"hello")  # should not raise

    def test_send_socket_error(self):
        conn = self._make_conn()
        sock = Mock()
        sock.sendall.side_effect = OSError("broken pipe")
        conn._sock = sock
        conn.send(b"hello")  # should not raise

    def test_handle_error(self):
        conn = self._make_conn()
        with patch("iotlabaggregator.connections.LOGGER") as mock_logger:
            try:
                raise ValueError("test error")
            except ValueError:
                conn.handle_error()
            mock_logger.error.assert_called_once()


class TestAggregator(unittest.TestCase):
    """Tests for the Aggregator class."""

    def test_empty_nodes_list_raises(self):
        self.assertRaises(ValueError, connections.Aggregator, [])

    def test_empty_nodes_list_message(self):
        with self.assertRaises(ValueError) as ctx:
            connections.Aggregator([])
        self.assertIn("Empty nodes list", str(ctx.exception))

    def test_init_creates_connections(self):
        agg = connections.Aggregator(["m3-1", "m3-2"])
        self.assertIn("m3-1", agg)
        self.assertIn("m3-2", agg)
        self.assertIsInstance(agg["m3-1"], connections.Connection)

    def test_broadcast(self):
        agg = connections.Aggregator(["m3-1", "m3-2"])
        agg["m3-1"].send = Mock()
        agg["m3-2"].send = Mock()
        agg.broadcast("hello")
        agg["m3-1"].send.assert_called_once_with(b"hello")
        agg["m3-2"].send.assert_called_once_with(b"hello")

    def test_send_nodes_broadcast(self):
        agg = connections.Aggregator(["m3-1"])
        agg["m3-1"].send = Mock()
        agg.send_nodes(None, "hello")
        agg["m3-1"].send.assert_called_once_with(b"hello")

    def test_send_nodes_specific(self):
        agg = connections.Aggregator(["m3-1", "m3-2"])
        agg["m3-1"].send = Mock()
        agg["m3-2"].send = Mock()
        agg.send_nodes(["m3-1"], "hello")
        agg["m3-1"].send.assert_called_once_with(b"hello")
        agg["m3-2"].send.assert_not_called()

    def test_send_unknown_node(self):
        agg = connections.Aggregator(["m3-1"])
        with patch("iotlabaggregator.connections.LOGGER") as mock_logger:
            agg._send("m3-99", "hello")
            mock_logger.warning.assert_called_once()

    def test_context_manager(self):
        agg = connections.Aggregator(["m3-1"])
        agg.start = Mock()
        agg.stop = Mock()
        with agg:
            agg.start.assert_called_once()
        agg.stop.assert_called_once()

    def test_custom_connection_class(self):
        class MyConn(connections.Connection):
            pass

        class MyAgg(connections.Aggregator):
            connection_class = MyConn

        agg = MyAgg(["m3-1"])
        self.assertIsInstance(agg["m3-1"], MyConn)

    def test_loop_exits_on_stop(self):
        """Verify the selector loop exits cleanly when _running is set False."""
        agg = connections.Aggregator(["m3-1"])
        selector = MagicMock()
        selector.select.return_value = []
        agg._selector = selector
        agg._running = True

        import threading

        def stop_soon():
            import time

            time.sleep(0.05)
            agg._running = False

        t = threading.Thread(target=stop_soon)
        t.start()
        agg._loop()
        t.join()
        # Should exit without sending SIGINT (self._running is False)
