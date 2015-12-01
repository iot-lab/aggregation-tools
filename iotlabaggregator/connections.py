#! /usr/bin/env python
# -*- coding:utf-8 -*-

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

""" Aggregate multiple tcp connections """

import socks
import socket
import errno

import os
import sys
import asyncore
from asyncore import dispatcher_with_send
import threading
import signal

from iotlabaggregator import LOGGER

# Use dispatcher_with_send to correctly implement buffered sending
# either we get 100% CPU as 'writeable' is always 'True
# http://stackoverflow.com/questions/22423625/ \
#     python-asyncore-using-100-cpu-after-client-connects
# Found dispatcher_with_send in the asyncore code


class Connection(object, dispatcher_with_send):  # pylint:disable=R0904
    """
    Handle the connection to one node
    Data is managed with asyncore. So to work asyncore.loop() should be run.

    Child class should re-implement 'handle_data'
    """
    port = 20000

    def __init__(self, hostname, aggregator):
        super(Connection, self).__init__()
        dispatcher_with_send.__init__(self)
        self.hostname = hostname  # node identifier for the user
        self.data_buff = ''       # received data buffer
        self.aggregator = aggregator

    def handle_data(self, data):
        """ Dummy handle data """
        LOGGER.info("%s received %u bytes", self.hostname, len(data))
        return ''  # Remaining unprocessed data

    # Overriding 'asyncore' functions
    def create_socket(self, family, type, proxy_port=None):
        self.family_and_type = family, type
        if proxy_port:
            sock = socks.socksocket(family, type)
            sock.set_proxy(socks.SOCKS5, 'localhost', proxy_port, rdns=True)
        else:
            sock = socket.socket(family, type)
        #sock.setblocking(0)
        self.set_socket(sock)

    def connect(self, address):
        self.connected = False
        self.connecting = True

        try:
            # Asyncore is using 'connect_hex' but not supported by PySocks
            self.socket.connect(address)
            self.socket.setblocking(0)  # Didn't work with non blocking socket
        except socks.ProxyConnectionError as err:
            # Handle 'non blocking socket' but failed
            sockerr = err.socket_err
            print sockerr
            if sockerr.args[0] not in (errno.EINPROGRESS, errno.EALREADY,
                                   errno.EWOULDBLOCK):
                raise sockerr
            print address
            self.addr = address
        else:
            self.addr = address
            self.handle_connect_event()
    # End of Overriding 'asyncore' functions

    def start(self):
        """ Connects to node serial port """
        self.data_buff = ''      # reset data
        #self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        if 'grenoble' in self.hostname:
            proxy_port = 1234
        elif 'strasbourg' in self.hostname:
            proxy_port = 1236
        else:
            proxy_port = None
        print self.hostname, proxy_port

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM,
                           proxy_port=proxy_port)
        self.connect((self.hostname, self.port))

    def handle_close(self):
        """ Close the connection and clear buffer """
        self.data_buff = ''
        LOGGER.error('%s;Connection closed', self.hostname)
        self.close()
        # remove itself from aggregator
        self.aggregator.pop(self.hostname, None)

    def handle_read(self):
        """ Append read bytes to buffer and run data handler. """
        self.data_buff += self.recv(8192)
        self.data_buff = self.handle_data(self.data_buff)

    def handle_error(self):
        """ Connection failed """
        LOGGER.error('%s;%r', self.hostname, sys.exc_info())


class Aggregator(dict):  # pylint:disable=too-many-public-methods
    """
    Create a dict of Connection from 'nodes_list'
    Each node is stored in the entry with it's node_id

    It as a thread that runs asyncore.loop() in the background.

    After init, it can be manipulated like a dict.
    """

    connection_class = Connection  # overriden in child class

    def __init__(self, nodes_list, *args, **kwargs):

        if not nodes_list:
            raise ValueError("%s: Empty nodes list %r" %
                             (self.__class__.__name__, nodes_list))
        super(Aggregator, self).__init__()
        self._running = False

        self.thread = threading.Thread(target=self._loop)
        # create all the Connections
        for node_url in nodes_list:
            node = self.connection_class(node_url, self, *args, **kwargs)
            self[node_url] = node

    def _loop(self):
        """ Run asyncore loop send SIGINT at the end to stop main process """
        asyncore.loop(timeout=1, use_poll=True)
        if self._running:  # Don't send signal if we are stopping
            LOGGER.info("Loop finished, all connection closed")
            os.kill(os.getpid(), signal.SIGINT)

    def start(self):
        """ Connect all nodes and run asyncore.loop in a thread """
        self._running = True
        for node in self.values():
            node.start()
        self.thread.start()
        LOGGER.info("Aggregator started")

    def stop(self):
        """ Stop the nodes connection and stop asyncore.loop thread """
        LOGGER.info("Stopping")
        self._running = False
        for node in self.values():
            node.close()
        self.thread.join()

    def run(self):  # pylint:disable=no-self-use
        """ Main function to run """
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
        """ Send the `message` to `nodes_list` nodes
        If nodes_list is None, send to all nodes """
        if nodes_list is None:
            LOGGER.debug("Broadcast: %r", message)
            self.broadcast(message)
        else:
            LOGGER.debug("Send: %r to %r", message, nodes_list)
            for node in nodes_list:
                self._send(node, message)

    def _send(self, hostname, message):
        """ Safe send message to node """
        try:
            self[hostname].send(message)
        except KeyError:
            LOGGER.warning("Node not managed: %s", hostname)
        except socket.error:
            LOGGER.warning("Send failed: %s", hostname)

    def broadcast(self, message):
        """ Send a message to all the nodes serial links """
        for node in self.keys():
            self._send(node, message)
