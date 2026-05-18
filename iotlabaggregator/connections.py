#! /usr/bin/env python

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

"""Aggregate multiple tcp connections"""

import os
import selectors
import signal
import socket
import sys
import threading

from iotlabaggregator import LOGGER


class Connection:
    """Handle the connection to one node.

    Child class should re-implement ``handle_data``.
    """

    port = 20000

    def __init__(self, hostname, aggregator):
        self.hostname = hostname
        self.data_buff = ""
        self.aggregator = aggregator
        self._sock = None
        self._send_lock = threading.Lock()

    def handle_data(self, data):
        """Dummy handle data."""
        LOGGER.info("%s received %u bytes", self.hostname, len(data))
        return ""  # Remaining unprocessed data

    def start(self):
        """Connect to node serial port."""
        self.data_buff = ""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self.hostname, self.port))

    def handle_close(self):
        """Close the connection and clear buffer."""
        self.data_buff = ""
        LOGGER.error("%s;Connection closed", self.hostname)
        self.close()
        self.aggregator.pop(self.hostname, None)

    def close(self):
        """Close the underlying socket."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def recv(self, n):
        """Receive up to n bytes from the socket."""
        return self._sock.recv(n)

    def send(self, data):
        """Send data to the node."""
        with self._send_lock:
            if self._sock is not None:
                try:
                    self._sock.sendall(data)
                except OSError:
                    pass

    def handle_read(self):
        """Append read bytes to buffer and run data handler."""
        self.data_buff += self.recv(8192).decode("utf-8", "replace")
        self.data_buff = self.handle_data(self.data_buff)

    def handle_error(self):
        """Log connection error."""
        LOGGER.error("%s;%r", self.hostname, sys.exc_info())


class Aggregator(dict):
    """Create a dict of Connection from ``nodes_list``.

    Each node is stored in the entry with its node_id.
    A background thread runs a selector loop to handle I/O.
    After init, it can be manipulated like a dict.
    """

    connection_class = Connection

    def __init__(self, nodes_list, *args, **kwargs):
        if not nodes_list:
            raise ValueError(
                f"{self.__class__.__name__}: Empty nodes list {nodes_list!r}"
            )
        super().__init__()
        self._running = False
        self._selector = selectors.DefaultSelector()
        self.thread = threading.Thread(target=self._loop)
        for node_url in nodes_list:
            node = self.connection_class(node_url, self, *args, **kwargs)
            self[node_url] = node

    def _loop(self):
        """Run selector loop; send SIGINT when all connections close."""
        while self._running:
            events = self._selector.select(timeout=1)
            for key, mask in events:
                conn = key.data
                if mask & selectors.EVENT_READ:
                    try:
                        conn.handle_read()
                    except OSError:
                        try:
                            self._selector.unregister(key.fileobj)
                        except (KeyError, ValueError):
                            pass
                        conn.handle_error()
        if self._running:
            LOGGER.info("Loop finished, all connections closed")
            os.kill(os.getpid(), signal.SIGINT)

    def start(self):
        """Connect all nodes and start the selector loop thread."""
        self._running = True
        for node in self.values():
            try:
                node.start()
            except OSError:
                node.handle_error()
                continue
            if node._sock is not None:
                self._selector.register(node._sock, selectors.EVENT_READ, data=node)
        self.thread.start()
        LOGGER.info("Aggregator started")

    def stop(self):
        """Stop all node connections and the selector loop thread."""
        LOGGER.info("Stopping")
        self._running = False
        for node in self.values():
            if node._sock is not None:
                try:
                    self._selector.unregister(node._sock)
                except (KeyError, ValueError):
                    pass
            node.close()
        self._selector.close()
        self.thread.join()

    def run(self):
        """Main function to run."""
        try:
            signal.pause()
        except KeyboardInterrupt:
            pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.stop()

    def send_nodes(self, nodes_list, message):
        """Send ``message`` to ``nodes_list`` nodes; broadcast if None."""
        if nodes_list is None:
            LOGGER.debug("Broadcast: %r", message)
            self.broadcast(message)
        else:
            LOGGER.debug("Send: %r to %r", message, nodes_list)
            for node in nodes_list:
                self._send(node, message)

    def _send(self, hostname, message):
        """Safely send a message to a single node."""
        try:
            self[hostname].send(message.encode("utf-8", "replace"))
        except KeyError:
            LOGGER.warning("Node not managed: %s", hostname)
        except OSError:
            LOGGER.warning("Send failed: %s", hostname)

    def broadcast(self, message):
        """Send a message to all nodes."""
        for node in self.keys():
            self._send(node, message)
