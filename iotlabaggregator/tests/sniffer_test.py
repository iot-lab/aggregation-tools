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

import binascii
import io
import sys
import unittest
from unittest.mock import MagicMock, Mock, patch

from iotlabaggregator import sniffer


class TestSnifferHandleRead(unittest.TestCase):
    """Test the packet reading code."""

    zep_message = binascii.a2b_hex(
        "".join(
            (
                "45 58 02 01"  # Base Zep header
                "0B 00 01 00 ff"  # chan | dev_id | dev_id| LQI/CRC_MODE |  LQI
                "00 00 00 00"  # Timestamp msb
                "00 00 00 00"  # timestamp lsp
                "00 00 00 01"  # seqno
                "00 01 02 03"  # reserved 0-3/10
                "04 05 06 07"  # reserved 4-7/10
                "08 09"  # reserved 8-9 / 10
                "08"  # Length 2 + data_len
                "61 62 63"  # Data
                "41 42 43"  # Data
                "FF FF"  # CRC)
            ).split()
        )
    )

    def setUp(self):
        self.outfd = Mock()

    def tearDown(self):
        patch.stopall()

    def test_simple(self):
        def recv(_):
            return self.zep_message

        aggregator = Mock()
        aggregator.rx_packets = 0
        sniff = sniffer.SnifferConnection("m3-1", aggregator, self.outfd.write)
        sniff.recv = Mock(side_effect=recv)
        sniff.handle_read()
        sniff.handle_read()
        msg = self.zep_message.decode("latin-1")
        self.outfd.write.assert_called_with(msg)

    def test_invalid_data_start(self):
        def recv(_):
            return b"invaEEEXlidE_data" + self.zep_message

        aggregator = Mock()
        aggregator.rx_packets = 0
        sniff = sniffer.SnifferConnection("m3-1", aggregator, self.outfd.write)
        sniff.recv = Mock(side_effect=recv)

        sniff.handle_read()
        sniff.handle_read()

        self.assertEqual(2, self.outfd.write.call_count)
        msg = self.zep_message.decode("latin-1")
        self.outfd.write.assert_called_with(msg)

    def test_read_ret_values(self):
        for i in range(1, 100):
            self.outfd.reset_mock()
            print(i)
            self.read_return_n_char_per_call(i)

    def read_return_n_char_per_call(self, num_chars):
        msg = list((self.zep_message).decode("latin-1") * 10)

        def recv(_):
            ret = msg[0:num_chars]
            del msg[0:num_chars]
            return ("".join(ret)).encode("latin-1")

        aggregator = Mock()
        aggregator.rx_packets = 0
        sniff = sniffer.SnifferConnection("m3-1", aggregator, self.outfd.write)
        sniff.recv = Mock(side_effect=recv)

        while msg:
            sniff.handle_read()
        self.assertEqual(10, self.outfd.write.call_count)
        msg = (self.zep_message).decode("latin-1")
        self.outfd.write.assert_called_with(msg)


class TestSnifferAggregatorSelectNodes(unittest.TestCase):
    """Tests for SnifferAggregator.select_nodes."""

    def setUp(self):
        self.get_exp = patch(
            "iotlabaggregator.common.experiment.get_experiment"
        ).start()
        self.get_exp.return_value = {
            "items": [
                {"network_address": "m3-1.grenoble.iot-lab.info", "site": "grenoble"},
                {"network_address": "a8-1.grenoble.iot-lab.info", "site": "grenoble"},
                {
                    "network_address": "nrf52840dk-1.grenoble.iot-lab.info",
                    "site": "grenoble",
                },
                {"network_address": "pc-1.grenoble.iot-lab.info", "site": "grenoble"},
            ]
        }
        patch("iotlabcli.get_current_experiment", return_value=123).start()
        patch("iotlabcli.get_user_credentials", return_value=("user", "pwd")).start()

    def tearDown(self):
        patch.stopall()

    @patch("iotlabaggregator.common.HOSTNAME", "grenoble")
    def test_select_nodes_filters_compat(self):
        opts = sniffer.SnifferAggregator.parser.parse_args(["-o", "-"])
        nodes = sniffer.SnifferAggregator.select_nodes(opts)
        # m3 and nrf52840dk are compatible; a8 is compatible; pc is not
        self.assertIn("m3-1", nodes)
        self.assertIn("a8-1", nodes)
        self.assertIn("nrf52840dk-1", nodes)
        self.assertNotIn("pc-1", nodes)

    @patch("iotlabaggregator.common.HOSTNAME", "grenoble")
    def test_select_nodes_empty_when_no_compat(self):
        self.get_exp.return_value = {
            "items": [
                {"network_address": "pc-1.grenoble.iot-lab.info", "site": "grenoble"},
            ]
        }
        opts = sniffer.SnifferAggregator.parser.parse_args(["-o", "-"])
        nodes = sniffer.SnifferAggregator.select_nodes(opts)
        self.assertEqual([], nodes)


class TestSnifferMain(unittest.TestCase):
    """Tests for sniffer.main() covering the file-open logic."""

    def setUp(self):
        # Keep the real parser so parse_args works normally
        real_parser = sniffer.SnifferAggregator.parser

        agg = MagicMock()
        agg.__enter__ = Mock(return_value=agg)
        agg.__exit__ = Mock(return_value=False)
        agg.rx_packets = 0

        self._cls = patch("iotlabaggregator.sniffer.SnifferAggregator").start()
        self._cls.parser = real_parser
        self._cls.select_nodes.return_value = ["m3-1"]
        self._cls.return_value = agg

    def tearDown(self):
        patch.stopall()

    def test_main_stdout(self):
        """-o - passes sys.stdout.buffer to the aggregator."""
        sniffer.main(["-o", "-"])
        outfd_used = self._cls.call_args[0][1]
        self.assertIs(sys.stdout.buffer, outfd_used)

    def test_main_file(self):
        """A path string is opened in wb mode and passed to the aggregator."""
        fake_file = io.BytesIO()
        with patch("builtins.open", return_value=fake_file) as mock_open:
            sniffer.main(["-o", "/tmp/out.pcap"])
        mock_open.assert_called_once_with("/tmp/out.pcap", "wb")
        outfd_used = self._cls.call_args[0][1]
        self.assertIs(fake_file, outfd_used)

    def test_main_empty_nodes_error(self):
        """ValueError (empty node list) is caught and exits with code 1."""
        self._cls.side_effect = ValueError("Empty nodes list")
        with self.assertRaises(SystemExit) as ctx:
            sniffer.main(["-o", "-"])
        self.assertEqual(1, ctx.exception.code)

    def test_main_debug_flag(self):
        """--debug raises the logger level to DEBUG."""
        import logging

        with patch("iotlabaggregator.sniffer.LOGGER") as mock_logger:
            sniffer.main(["-o", "-", "--debug"])
        mock_logger.setLevel.assert_called_once_with(logging.DEBUG)
