#! /usr/bin/python
# -*- coding: utf-8 -*-

""" Sniff tcp socket zep messages and save them as pcap """

# pylint:disable=too-few-public-methods

import argparse
import sys
import logging

import iotlabaggregator
from iotlabaggregator import connections, common, zeptopcap


class SnifferConnection(connections.Connection):
    """ Connection to sniffer and data handling """
    port = 30000
    zep_hdr_len = zeptopcap.ZepPcap.zep_hdr_len

    def __init__(self, hostname, pkt_handler):
        super(SnifferConnection, self).__init__(hostname)
        self.pkt_handler = pkt_handler

    def handle_data(self, data):
        """ Print the data received line by line """

        while True:
            data = self._strip_until_pkt_start(data)
            if not data.startswith('EX\2') or len(data) < self.zep_hdr_len:
                break
            # length = header length + data['len_byte']
            full_len = self.zep_hdr_len + ord(data[self.zep_hdr_len - 1])
            if len(data) < full_len:
                break

            # Extract packet
            pkt, data = data[:full_len], data[full_len:]
            iotlabaggregator.LOGGER.debug('%s;Packet received len: %d',
                                          self.hostname, full_len)
            self.pkt_handler(pkt)

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
            iotlabaggregator.LOGGER.setLevel(logging.DEBUG)
        # Run the aggregator
        with SnifferAggregator(nodes_list, opts.outfd, opts.raw) as aggregator:
            aggregator.run()
    except (ValueError, RuntimeError) as err:
        sys.stderr.write("%s\n" % err)
        exit(1)
