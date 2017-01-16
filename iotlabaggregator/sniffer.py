#! /usr/bin/python
# -*- coding: utf-8 -*-

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

""" Sniff tcp socket zep messages and save them as pcap """

# pylint versions have different outputs...
# pylint:disable=too-few-public-methods
# pylint:disable=too-many-public-methods

import argparse
import sys
import logging

from iotlabaggregator import connections, common, zeptopcap, LOGGER

# pylint: disable=wrong-import-order
try:
    # pylint: disable=import-error,no-name-in-module
    from urllib.error import HTTPError
except ImportError:  # pragma: no cover
    # pylint: disable=import-error,no-name-in-module
    from urllib2 import HTTPError


class SnifferConnection(connections.Connection):
    """ Connection to sniffer and data handling """
    port = 30000
    ZEP_HDR_LEN = zeptopcap.ZepPcap.ZEP_HDR_LEN

    def __init__(self, hostname, aggregator, pkt_handler):
        super(SnifferConnection, self).__init__(hostname, aggregator)
        self.pkt_handler = pkt_handler

    def handle_data(self, data):
        """ Print the data received line by line """

        while True:
            data = self._strip_until_pkt_start(data)
            if not data.startswith('EX\2') or len(data) < self.ZEP_HDR_LEN:
                break
            # length = header length + data['len_byte']
            full_len = self.ZEP_HDR_LEN + ord(data[self.ZEP_HDR_LEN - 1])
            if len(data) < full_len:
                break

            # Extract packet
            pkt, data = data[:full_len], data[full_len:]
            LOGGER.debug('%s;Packet received len: %d', self.hostname, full_len)
            self.pkt_handler(pkt)
            self.aggregator.rx_packets += 1

        return data

    @staticmethod
    def _strip_until_pkt_start(msg):
        """
        >>> msg = 'abcdEEEEEEEEEX\2'
        >>> 'EX\2' == SnifferConnection._strip_until_pkt_start(msg)
        True

        >>> msg = 'abcdEEEEEEEEEX\2' '12345'
        >>> 'EX\2''12345' == SnifferConnection._strip_until_pkt_start(msg)
        True

        >>> msg = 'abcdEEE'
        >>> 'EE' == SnifferConnection._strip_until_pkt_start(msg)
        True

        >>> msg = 'abcdEEEa'
        >>> 'Ea' == SnifferConnection._strip_until_pkt_start(msg)
        True

        >>> msg = 'a'
        >>> 'a' == SnifferConnection._strip_until_pkt_start(msg)
        True

        """
        whole_index = msg.find('EX\2')
        if whole_index == 0:   # is stripped
            return msg
        if whole_index != -1:  # found, strip first lines
            return msg[whole_index:]

        # not found but remove some chars from the buffer
        # at max 2 required in this case
        # might be invalid packet but keeps buffer small anymay
        return msg[-2:]


class SnifferAggregator(connections.Aggregator):
    """ Aggregator for the Sniffer """
    connection_class = SnifferConnection

    parser = argparse.ArgumentParser()
    common.add_nodes_selection_parser(parser)
    _output = parser.add_argument_group("Sniffer output")
    _output.add_argument(
        '-o', '--outfile', metavar='PCAP_FILE', dest='outfd',
        type=argparse.FileType('wb'), required=True,
        help="Pcap outfile. Use '-' for stdout.")
    _output.add_argument(
        '-d', '--debug', action='store_true', default=False,
        help="Print debug on received packets")
    _output.add_argument(
        '-r', '--raw', '--foren6', action='store_true', default=False,
        help="Extract payload and no encapsulation. For foren6.")

    def __init__(self, nodes_list, outfd, raw=False, *args, **kwargs):
        zep_pcap = zeptopcap.ZepPcap(outfd, raw)
        super(SnifferAggregator, self).__init__(
            nodes_list, pkt_handler=zep_pcap.write, *args, **kwargs)
        self.rx_packets = 0

    @staticmethod
    def select_nodes(opts):
        """ Select all gateways that support sniffer """
        nodes = common.get_nodes_selection(**vars(opts))
        nodes_list = [n for n in nodes if n.startswith(('m3', 'a8'))]
        return nodes_list


def main(args=None):
    """ Aggregate all nodes radio sniffer """
    args = args or sys.argv[1:]
    opts = SnifferAggregator.parser.parse_args(args)
    try:
        # Parse arguments
        nodes_list = SnifferAggregator.select_nodes(opts)
        if opts.debug:
            LOGGER.setLevel(logging.DEBUG)
        # Run the aggregator
        with SnifferAggregator(nodes_list, opts.outfd, opts.raw) as aggregator:
            aggregator.run()
            LOGGER.info('%u packets captured', aggregator.rx_packets)
    except (ValueError, RuntimeError) as err:
        sys.stderr.write("%s\n" % err)
        exit(1)
    except HTTPError as err:  # should be first as it's an IOError
        if err.code == 401:
            # print an info on how to get rid of the error
            err = ("HTTP Error 401: Unauthorized: Wrong login/password\n\n"
                   "\tRegister your login:password using `auth-cli`\n")
        sys.stderr.write("{0}\n".format(err))
        exit(1)
