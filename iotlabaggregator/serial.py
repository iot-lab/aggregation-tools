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

"""
Serial aggregator
=================

Take an experiment description as input.
Gather all nodes output to stdout, prefixed by the node number and timestamp.

    1395240359.286712;node46; Type Enter to stop printing this help
    1395240359.286853;node46;
    1395240359.292523;node9;
    1395240359.292675;node9;Senslab Simple Demo program

Usage
-----

On each server your experiment is run on:

    $ ./serial_aggregator.py [opts]
    1395240359.286712;node46; Type Enter to stop printing this help
    1395240359.286853;node46;
    1395240359.292523;node9;
    1395240359.292675;node9;Senslab Simple Demo program


Warning
-------

If a node sends only characters without newlines, the output is never printed.
To give a 'correct' looking output, only lines are printed.


### Multi sites experiments ###

The script will get the serial links current site nodes.
For multi-sites experiments, you should run the script on each site server.
"""
# pylint versions have different outputs...
# pylint:disable=too-few-public-methods
# pylint:disable=too-many-public-methods

# use readline for 'raw_input'
from builtins import input
import readline  # noqa  # pylint:disable=unused-import

import logging
import sys
import argparse


from iotlabcli.parser import common as common_parser

from iotlabaggregator import connections, common, LOG_FMT

try:
    import colorama  # pylint:disable=import-error
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


# Declare color specific functions
if HAS_COLOR:
    colorama.init()
    _COLOR = [colorama.Fore.BLACK, colorama.Fore.RED,
              colorama.Fore.GREEN, colorama.Fore.YELLOW,
              colorama.Fore.BLUE, colorama.Fore.MAGENTA,
              colorama.Fore.CYAN, colorama.Fore.WHITE]
    COLOR_RESET = str(colorama.Fore.RESET)

    def _color_hash(string):
        """Return a hash of the string."""
        return sum(ord(c) for c in string)

    def color_str(string):
        """Return color string character for identifier."""
        color_idx = _color_hash(string) % len(_COLOR)
        return str(_COLOR[color_idx])
else:
    COLOR_RESET = ''

    def color_str(_):
        """No color."""
        return ''


class SerialConnection(connections.Connection):  # pylint:disable=R0903,R0904
    """
    Handle the connection to one node serial link.
    Data is managed with asyncore. So to work asyncore.loop() should be run.

    :param print_lines: should lines be printed to stdout
    :param line_handler: additional function to call on received lines.
        `line_handler(identifier, line)`
    """
    port = 20000

    _line_logger = logging.StreamHandler(sys.stdout)
    _line_logger.setFormatter(LOG_FMT)
    logger = logging.getLogger('SerialConnection')
    logger.setLevel(logging.INFO)
    logger.addHandler(_line_logger)

    # pylint:disable=bad-option-value,too-many-arguments,super-on-old-class,super-with-arguments
    def __init__(self,
                 hostname, aggregator,
                 print_lines=False, line_handler=None, color=False):
        super(SerialConnection, self).__init__(hostname, aggregator)

        self.line_handler = common.Event()
        if print_lines:
            self.line_handler.append(self.print_line)
        if line_handler:
            self.line_handler.append(line_handler)

        self.fmt = '%s;%s'
        if color:
            self.fmt = f'{color_str(self.hostname)}{self.fmt}{COLOR_RESET}'

    def handle_data(self, data):
        """ Print the data received line by line """

        lines = data.splitlines(True)
        data = ''
        for line in lines:
            if line[-1] == '\n':
                line = line[:-1]
                self.line_handler(self.hostname, line)
            else:
                data = line  # last incomplete line
        return data

    def print_line(self, identifier, line):
        """ Print one line prefixed by id in format: """
        self.logger.info(self.fmt, identifier, line)


class SerialAggregator(connections.Aggregator):
    """ Aggregator for the Serial """
    connection_class = SerialConnection

    parser = argparse.ArgumentParser()
    common.add_nodes_selection_parser(parser)
    parser.add_argument(
        '--with-a8', action='store_true',
        help=('redirect open-a8 serial port. ' +
              '`/etc/init.d/serial_redirection` must be running on the nodes'))

    # Add 'opts.color' no error if no available
    parser.set_defaults(color=False)
    if HAS_COLOR:
        parser.add_argument(
            '--color', action='store_true', default=False,
            help='Add color to node lines.',
        )

    @staticmethod
    def select_nodes(opts):
        """ Select all gateways and open-a8 if `with_a8` """
        nodes = common.get_nodes_selection(**vars(opts))

        # all gateways urls except A8
        nodes_list = [n for n in nodes if not n.startswith('a8')]

        # add open-a8 urls with 'node-' in front all urls
        if opts.with_a8:
            nodes_list += ['node-' + n for n in nodes if n.startswith('a8')]
        return nodes_list

    def run(self):  # overwrite original function
        """ Read standard input while aggregator is running """
        try:
            self.read_input()
        except (KeyboardInterrupt, EOFError):
            pass

    def read_input(self):
        """ Read input and sends the messages to the given nodes """
        while True:
            line = input()
            nodes, message = self.extract_nodes_and_message(line)

            if (None, '') != (nodes, message):
                self.send_nodes(nodes, message + '\n')
            # else: Only hitting 'enter' to get spacing

    @staticmethod
    def extract_nodes_and_message(line):
        """
        >>> SerialAggregator.extract_nodes_and_message('')
        (None, '')

        >>> SerialAggregator.extract_nodes_and_message(' ')
        (None, ' ')

        >>> SerialAggregator.extract_nodes_and_message('message')
        (None, 'message')

        >>> SerialAggregator.extract_nodes_and_message('-;message')
        (None, 'message')

        >>> SerialAggregator.extract_nodes_and_message('my_message_csv;msg')
        (None, 'my_message_csv;msg')

        >>> SerialAggregator.extract_nodes_and_message('M3,1;message')
        (['m3-1'], 'message')

        >>> SerialAggregator.extract_nodes_and_message('m3,1-3+5;message')
        (['m3-1', 'm3-2', 'm3-3', 'm3-5'], 'message')

        >>> SerialAggregator.extract_nodes_and_message('wsn430,3+5;message')
        (['wsn430-3', 'wsn430-5'], 'message')

        >>> SerialAggregator.extract_nodes_and_message('a8,1+2;message')
        (['node-a8-1', 'node-a8-2'], 'message')

        # use dash in node destination
        >>> SerialAggregator.extract_nodes_and_message('m3-1;message')
        (['m3-1'], 'message')

        >>> SerialAggregator.extract_nodes_and_message('A8-1;message')
        (['node-a8-1'], 'message')

        >>> SerialAggregator.extract_nodes_and_message('node-a8-1;message')
        (['node-a8-1'], 'message')

        """
        try:
            nodes_str, message = line.split(';')
            if nodes_str == '-':
                # -
                return None, message

            if ',' in nodes_str:
                # m3,1-5+4
                archi, list_str = nodes_str.split(',')
            else:
                # m3-1 , a8-2, node-a8-3, wsn430-4
                # convert it as if it was with a comma
                archi, list_str = nodes_str.rsplit('-', 1)
                int(list_str)  # ValueError if not int

            # normalize archi
            archi = archi.lower()
            archi = 'node-a8' if archi == 'a8' else archi

            # get nodes list
            nodes = common_parser.nodes_id_list(archi, list_str)

            return nodes, message
        except (IndexError, ValueError):
            return None, line


def main(args=None):
    """ Aggregate all nodes sniffer """
    args = args or sys.argv[1:]
    opts = SerialAggregator.parser.parse_args(args)
    try:
        # Parse arguments
        nodes_list = SerialAggregator.select_nodes(opts)
        # Run the aggregator
        with SerialAggregator(nodes_list, print_lines=True,
                              color=opts.color) as aggregator:
            aggregator.run()
    except (ValueError, RuntimeError) as err:
        sys.stderr.write(f"{err}\n")
        sys.exit(1)
