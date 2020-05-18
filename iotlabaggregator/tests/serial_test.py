#! /usr/bin/python
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

# pylint:disable=missing-docstring

import unittest
import mock

from iotlabaggregator import serial


class TestSelectNodes(unittest.TestCase):
    def setUp(self):
        self.get_exp = mock.patch('iotlabaggregator.common.experiment'
                                  '.get_experiment').start()
        self.get_exp.side_effect = self._get_exp
        self.cur_exp = mock.patch('iotlabcli.get_current_experiment').start()
        self.cur_exp.return_value = 123

        sites_list = mock.patch('iotlabcli.parser.common.sites_list').start()
        sites_list.return_value = ['grenoble', 'lille', 'strasbourg']

        credentials = mock.patch('iotlabcli.get_user_credentials').start()
        credentials.return_value = ('user', 'password')

    def tearDown(self):
        mock.patch.stopall()

    def _get_exp(self, _api, _exp_id,  # pylint:disable=unused-argument
                 option=''):
        if option == '':
            return {'state': 'Running'}
        elif option == 'nodes':
            resources = {"items": [
                {'network_address': 'm3-1.grenoble.iot-lab.info',
                 'site': 'grenoble'},
                {'network_address': 'wsn430-1.lille.iot-lab.info',
                 'site': 'lille'},
                {'network_address': 'a8-1.strasbourg.iot-lab.info',
                 'site': 'strasbourg'},
                {'network_address': 'wsn430-4.grenoble.iot-lab.info',
                 'site': 'grenoble'},
                {'network_address': 'a8-1.grenoble.iot-lab.info',
                 'site': 'grenoble'},
            ]}
            return resources
        return self.fail()

    @mock.patch('iotlabaggregator.common.HOSTNAME', 'grenoble')
    def test_no_args(self):
        opts = serial.SerialAggregator.parser.parse_args([])
        nodes_list = serial.SerialAggregator.select_nodes(opts)
        # Only grenoble nodes, m3 and wsn430
        self.assertEqual(['m3-1', 'wsn430-4'], nodes_list)

        opts = serial.SerialAggregator.parser.parse_args(['--with-a8'])
        nodes_list = serial.SerialAggregator.select_nodes(opts)
        # Also a8 nodes
        self.assertEqual(['m3-1', 'wsn430-4', 'node-a8-1'], nodes_list)

    @mock.patch('iotlabaggregator.common.HOSTNAME', 'grenoble')
    def test_node_selection(self):
        opts = serial.SerialAggregator.parser.parse_args(
            ['-l', 'grenoble,m3,1-5'])
        nodes_list = serial.SerialAggregator.select_nodes(opts)
        self.assertEqual(['m3-1', 'm3-2', 'm3-3', 'm3-4', 'm3-5'], nodes_list)

        # nodes from another site
        opts = serial.SerialAggregator.parser.parse_args(
            ['-l', 'grenoble,m3,1', '-l', 'lille,wsn430,1'])
        nodes_list = serial.SerialAggregator.select_nodes(opts)
        self.assertEqual(['m3-1'], nodes_list)


class TestColor(unittest.TestCase):

    def test_has_color(self):
        # pylint:disable=bad-option-value,import-error,import-outside-toplevel
        if serial.HAS_COLOR:
            import colorama as _  # noqa
        else:
            self.assertRaises(ImportError, __import__, 'colorama')
