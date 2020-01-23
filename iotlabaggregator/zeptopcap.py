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


""" Generate pcap files from zep messages """

#  http://www.codeproject.com/Tips/612847/ \
#      Generate-a-quick-and-easy-custom-pcap-file-using-P

import sys
import struct
import binascii


class ZepPcap():  # pylint:disable=too-few-public-methods
    """ Zep to Pcap converter
    On `write` encapsulate the message as a zep packet in `outfile` pcap format
    """
    ZEP_PORT = 17754
    ZEP_HDR_LEN = 32
    ZEP_TIME_IDX = 9
    # http://www.tcpdump.org/linktypes.html
    LINKTYPE_ETHERNET = 1
    LINKTYPE_IEEE802_15_4 = 195  # with FCS

    # 1970 - 1900 in seconds
    NTP_JAN_1970 = 2208988800
    NTP_SECONDS_FRAC = 1 << 32

    # Network headers as network endian
    eth_hdr = struct.pack('!3H3HH',
                          0, 0, 0,  # dst mac addr
                          0, 0, 0,  # src mac addr
                          0x0800)   # Protocol: (0x0800 == IP)

    def __init__(self, outfile, raw=False):
        self.out = outfile

        # configure "raw" mode
        # On raw, use linktype 802.15_4 else ethernet encapsulation
        self.write = self._write_raw if raw else self._write_zep
        link = self.LINKTYPE_IEEE802_15_4 if raw else self.LINKTYPE_ETHERNET

        # Write global header
        hdr = self._main_pcap_header(link)
        self.out.write(hdr)
        self.out.flush()

    def _write_zep(self, packet):
        """ Encapsulate ZEP data in pcap outfile """
        timestamp = self._timestamp(packet)

        # Calculate all headers
        length = len(packet)

        udp_hdr = self._udp_header(length)
        length += len(udp_hdr)

        ip_hdr = self._ip_header(length)
        length += len(ip_hdr)

        eth_hdr = self._eth_header(length)
        length += len(eth_hdr)

        pcap_hdr = self._pcap_header(length, timestamp[0], timestamp[1])
        length += len(pcap_hdr)

        # Actually write the data
        self.out.write(pcap_hdr)
        self.out.write(eth_hdr)
        self.out.write(ip_hdr)
        self.out.write(udp_hdr)
        self.out.write(packet)
        self.out.flush()

    def _write_raw(self, packet):
        """ Only write the ZEP payload as pcap"""
        timestamp = self._timestamp(packet)

        # extract payload from zep encapsulated data
        payload = packet[self.ZEP_HDR_LEN:]

        # Only add pcap header
        length = len(payload)
        pcap_hdr = self._pcap_header(length, timestamp[0], timestamp[1])
        length += len(pcap_hdr)

        # Actually write the data
        self.out.write(pcap_hdr)
        self.out.write(payload)
        self.out.flush()

    def _timestamp(self, packet):
        """ Extract packet timestamp as an unix time tuple (s, us)
        Packet timestamp is in 'ntp' format.

        MSB are seconds stored since 1 january 1900
        LSB are fraction of seconds where 2**32 == 1 second
        """
        ntp_t = struct.unpack_from('!LL', packet, self.ZEP_TIME_IDX)

        t_s = ntp_t[0] - self.NTP_JAN_1970
        t_us = (1000000 * ntp_t[1]) / self.NTP_SECONDS_FRAC

        return t_s, t_us

    def _udp_header(self, pkt_len):
        """ Get UDP Header

        2B - src_port: ZEP_PORT also but not required
        2B - dst_port: ZEP_PORT == 17754
        2B - length:   header + packet length
        2B - checksum: Disable == 0

        """
        hdr_struct = struct.Struct('!HHHH')
        udp_len = hdr_struct.size + pkt_len
        udp_hdr = hdr_struct.pack(self.ZEP_PORT, self.ZEP_PORT, udp_len, 0)
        return udp_hdr

    def _ip_header(self, pkt_len):
        """ Get the IP Header

        1B - Version | IHL:           0x45: [4 | 5] : [4b | 4b]
        1B - Type of Service:         0
        2B - Length:                  pkt_len + Header length
        2B - Identification:          0
        2B - Flags | Fragment offset: 0x4000: [2 | 0] : [3b | 13b]
        1B - TTL:                     0xff
        1B - Protocol:                0x11 UDP
        2B - Checksum:                calculated
        4B - Source Address:          0x7F000001 (127.0.0.1)
        4B - Destination Address:     0x7F000001 (127.0.0.1)

        """
        hdr_struct = struct.Struct('!BBHHHBBHLL')
        ip_len = hdr_struct.size + pkt_len

        # generate header with checksum == 0 to calculate checksum
        checksum = 0
        ip_hdr_csum = hdr_struct.pack(0x45, 0, ip_len, 0, 0x4000, 0xff, 0x11,
                                      checksum, 0x7F000001, 0x7F000001)
        checksum = self._ip_checksum(ip_hdr_csum)

        # Generate header with correct checksum
        ip_hdr = hdr_struct.pack(0x45, 0, ip_len, 0, 0x4000, 0xff, 0x11,
                                 checksum, 0x7F000001, 0x7F000001)
        return ip_hdr

    def _eth_header(self, pkt_len):  # pylint:disable=unused-argument
        """ Return a static empty ethernet header

        6B - dst mac addr: 0
        6B - src mac addr: 0
        2B - protocol:     0x0800 (IP)
        """
        return self.eth_hdr

    @staticmethod
    def _pcap_header(pkt_len, t_s, t_us):
        """ Get the PCAP Header

        4B - Timestamp seconds:      current time
        4B - Timestamp microseconds: current time
        4B - Number of octet saved:  pkt_len
        4B - Actual lengt of packet: pkt_len
        """

        hdr_struct = struct.Struct('=LLLL')
        pcap_len = pkt_len
        pcap_hdr = hdr_struct.pack(t_s, t_us, pcap_len, pcap_len)
        return pcap_hdr

    @staticmethod
    def _ip_checksum(hdr):
        """ Calculate the ip checksum for given header """
        assert (len(hdr) % 2) == 0  # hdr has even length
        word_pack = struct.Struct('!H')

        # Sum all 16bits
        hdr_split = (hdr[i:i+2] for i in range(0, len(hdr), 2))
        csum = sum((word_pack.unpack(word)[0] for word in hdr_split))

        # Reduce to 16b and save the one complement
        checksum = (csum + (csum >> 16)) & 0xFFFF ^ 0xFFFF
        return checksum

    @staticmethod
    def _main_pcap_header(link_type):
        """ Return the main pcap file header for `link_type`

        PCAP headers as native endian
        """
        return struct.pack(
            '=LHHLLLL',
            0xa1b2c3d4,  # Pcap header Little Endian
            2,           # File format major revision (i.e. pcap <2>.4)
            4,           # File format minor revision (i.e. pcap 2.<4>)
            0,           # GMT to local correction: 0 if timestamps are UTC
            0,           # accuracy of timestamps -> set it to 0
            0xffff,      # packet capture limit -> typically 65535
            link_type,   # Link (Ethernet/802.15.4 FCS/...)
        )


def main():
    """ Main function """

    zep_message_str = (
        '45 58 02 01'   # Base Zep header
        '0B 00 01 00 ff'   # chan | dev_id | dev_id| LQI/CRC_MODE |  LQI
        '00 00 00 00'   # Timestamp msb
        '00 00 00 00'   # timestamp lsp

        '00 00 00 01'   # seqno

        '00 01 02 03'   # reserved 0-3/10
        '04 05 16 07'   # reserved 4-7/10
        '08 09'         # reserved 8-9 / 10
        '08'            # Length 2 + data_len
        '61 62 63'      # Data
        '41 42 43'      # Data
        'FF FF'         # CRC)
    )
    zep_message = binascii.a2b_hex(''.join(zep_message_str.split()))

    out_file = sys.argv[1]
    with open(out_file, 'w') as pcap_file:
        zep_pcap = ZepPcap(pcap_file)

        zep_pcap.write(zep_message)
        zep_pcap.write(zep_message)
        zep_pcap.write(zep_message)
        zep_pcap.write(zep_message)
        zep_pcap.write(zep_message)


if __name__ == '__main__':
    main()
