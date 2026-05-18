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

"""Tests for iotlabaggregator.zeptopcap"""

import binascii
import io
import struct
import unittest

from iotlabaggregator import zeptopcap

ZEP_MESSAGE = binascii.a2b_hex(
    "".join(
        (
            "45 58 02 01"  # Base Zep header
            "0B 00 01 00 ff"  # chan | dev_id | dev_id | LQI/CRC_MODE | LQI
            "00 00 00 00"  # Timestamp msb
            "00 00 00 00"  # timestamp lsp
            "00 00 00 01"  # seqno
            "00 01 02 03"  # reserved 0-3/10
            "04 05 06 07"  # reserved 4-7/10
            "08 09"  # reserved 8-9/10
            "08"  # Length 2 + data_len
            "61 62 63"  # Data
            "41 42 43"  # Data
            "FF FF"  # CRC
        ).split()
    )
)

# Same as ZEP_MESSAGE but with a valid NTP timestamp (Jan 1 2024 = 0xE949B200)
# so that write tests produce valid pcap timestamps (no overflow)
ZEP_MESSAGE_VALID_TS = binascii.a2b_hex(
    "".join(
        (
            "45 58 02 01"  # Base Zep header
            "0B 00 01 00 ff"  # chan | dev_id | dev_id | LQI/CRC_MODE | LQI
            "E9 49 B2 00"  # Timestamp msb (NTP Jan 1 2024 00:00:00 UTC)
            "00 00 00 00"  # Timestamp lsp (fraction = 0)
            "00 00 00 01"  # seqno
            "00 01 02 03"  # reserved 0-3/10
            "04 05 06 07"  # reserved 4-7/10
            "08 09"  # reserved 8-9/10
            "08"  # Length 2 + data_len
            "61 62 63"  # Data
            "41 42 43"  # Data
            "FF FF"  # CRC
        ).split()
    )
)


class TestZepPcapHeaders(unittest.TestCase):
    """Tests for ZepPcap header generation."""

    def setUp(self):
        self.out = io.BytesIO()
        self.zep = zeptopcap.ZepPcap(self.out)

    def test_main_pcap_header_written_on_init(self):
        # After init, the global PCAP header should be written
        data = self.out.getvalue()
        self.assertGreater(len(data), 0)
        magic, major, minor = struct.unpack_from("=LHH", data, 0)
        self.assertEqual(0xA1B2C3D4, magic)
        self.assertEqual(2, major)
        self.assertEqual(4, minor)

    def test_main_pcap_header_raw_mode(self):
        out = io.BytesIO()
        zeptopcap.ZepPcap(out, raw=True)
        data = out.getvalue()
        # link type for raw mode is LINKTYPE_IEEE802_15_4 = 195
        link_type = struct.unpack_from("=L", data, 20)[0]
        self.assertEqual(195, link_type)

    def test_main_pcap_header_zep_mode(self):
        # link type for zep mode is LINKTYPE_ETHERNET = 1
        data = self.out.getvalue()
        link_type = struct.unpack_from("=L", data, 20)[0]
        self.assertEqual(1, link_type)

    def test_udp_header(self):
        hdr = self.zep._udp_header(10)
        self.assertEqual(8 + 10, struct.unpack("!H", hdr[4:6])[0])

    def test_ip_header_length(self):
        hdr = self.zep._ip_header(0)
        self.assertEqual(20, len(hdr))

    def test_ip_header_protocol_udp(self):
        hdr = self.zep._ip_header(0)
        # Protocol byte is at offset 9
        self.assertEqual(0x11, hdr[9])

    def test_eth_header_length(self):
        hdr = self.zep._eth_header(100)
        self.assertEqual(14, len(hdr))

    def test_pcap_header(self):
        hdr = zeptopcap.ZepPcap._pcap_header(40, 1000, 500)
        ts_s, ts_us, pkt_len, orig_len = struct.unpack("=LLLL", hdr)
        self.assertEqual(1000, ts_s)
        self.assertEqual(500, ts_us)
        self.assertEqual(40, pkt_len)
        self.assertEqual(40, orig_len)

    def test_ip_checksum_all_zeros(self):
        hdr = b"\x00" * 20
        csum = zeptopcap.ZepPcap._ip_checksum(hdr)
        self.assertEqual(0xFFFF, csum)

    def test_ip_checksum_nonzero(self):
        # A known valid IP header should produce checksum 0 when re-checked
        # (XOR with 0xFFFF of sum gives 0 when checksum field is correct)
        hdr_struct = struct.Struct("!BBHHHBBHLL")
        ip_hdr = hdr_struct.pack(
            0x45, 0, 20, 0, 0x4000, 0xFF, 0x11, 0, 0x7F000001, 0x7F000001
        )
        csum = zeptopcap.ZepPcap._ip_checksum(ip_hdr)
        self.assertNotEqual(0, csum)


class TestZepPcapTimestamp(unittest.TestCase):
    """Tests for timestamp extraction."""

    def setUp(self):
        self.out = io.BytesIO()
        self.zep = zeptopcap.ZepPcap(self.out)

    def test_timestamp_epoch(self):
        # Build a packet with NTP timestamp = NTP_JAN_1970 → unix time 0
        packet = bytearray(40)
        packet[0:4] = b"EX\x02\x01"
        ntp_seconds = zeptopcap.ZepPcap.NTP_JAN_1970
        struct.pack_into("!LL", packet, zeptopcap.ZepPcap.ZEP_TIME_IDX, ntp_seconds, 0)
        t_s, t_us = self.zep._timestamp(bytes(packet))
        self.assertEqual(0, t_s)
        self.assertEqual(0, t_us)

    def test_timestamp_fractional(self):
        packet = bytearray(40)
        ntp_seconds = zeptopcap.ZepPcap.NTP_JAN_1970 + 1
        ntp_frac = zeptopcap.ZepPcap.NTP_SECONDS_FRAC // 2  # 0.5 seconds → 500000 us
        struct.pack_into(
            "!LL", packet, zeptopcap.ZepPcap.ZEP_TIME_IDX, ntp_seconds, ntp_frac
        )
        t_s, t_us = self.zep._timestamp(bytes(packet))
        self.assertEqual(1, t_s)
        self.assertEqual(500000, t_us)


class TestZepPcapWrite(unittest.TestCase):
    """Integration tests for ZepPcap.write."""

    def test_write_zep_produces_output(self):
        out = io.BytesIO()
        zep = zeptopcap.ZepPcap(out)
        initial_len = len(out.getvalue())
        zep.write(ZEP_MESSAGE_VALID_TS.decode("latin-1"))
        self.assertGreater(len(out.getvalue()), initial_len)

    def test_write_raw_produces_output(self):
        out = io.BytesIO()
        zep = zeptopcap.ZepPcap(out, raw=True)
        initial_len = len(out.getvalue())
        zep.write(ZEP_MESSAGE_VALID_TS.decode("latin-1"))
        self.assertGreater(len(out.getvalue()), initial_len)

    def test_write_zep_pcap_record_length(self):
        """Written pcap record must contain ethernet+ip+udp+zep payload."""
        out = io.BytesIO()
        zep = zeptopcap.ZepPcap(out)
        header_size = len(out.getvalue())
        zep.write(ZEP_MESSAGE_VALID_TS.decode("latin-1"))
        record = out.getvalue()[header_size:]
        # pcap record header: 8 bytes timestamps + 4 bytes captured len + 4 bytes orig len
        pkt_len = struct.unpack_from("=L", record, 8)[0]
        # eth(14) + ip(20) + udp(8) + zep_payload(40)
        self.assertEqual(14 + 20 + 8 + len(ZEP_MESSAGE_VALID_TS), pkt_len)

    def test_write_raw_pcap_record_length(self):
        """Raw mode writes only payload (strips ZEP header)."""
        out = io.BytesIO()
        zep = zeptopcap.ZepPcap(out, raw=True)
        header_size = len(out.getvalue())
        zep.write(ZEP_MESSAGE_VALID_TS.decode("latin-1"))
        record = out.getvalue()[header_size:]
        pkt_len = struct.unpack_from("=L", record, 8)[0]
        expected = len(ZEP_MESSAGE_VALID_TS) - zeptopcap.ZepPcap.ZEP_HDR_LEN
        self.assertEqual(expected, pkt_len)
