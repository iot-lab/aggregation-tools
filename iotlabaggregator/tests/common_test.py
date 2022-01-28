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
# pylint:disable=invalid-name

import unittest
from mock import patch
try:
    from urllib.error import HTTPError
    from io import StringIO
except ImportError:
    from urllib2 import HTTPError
    from cStringIO import StringIO
from iotlabaggregator import common


class TestCommonFunctions(unittest.TestCase):

    @patch('iotlabcli.get_current_experiment')
    @patch('iotlabaggregator.common.experiment.get_experiment')
    def test_query_nodes(self, get_exp, get_cur_exp):
        api = None
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
        get_exp.return_value = resources
        get_cur_exp.return_value = 123

        # without exp_id
        ret = common.query_nodes(api, hostname='strasbourg')
        self.assertEqual(['a8-1'], ret)

        # with exp_id
        ret = common.query_nodes(api, exp_id=123, hostname='grenoble')
        self.assertEqual(['a8-1', 'm3-1', 'wsn430-4'], ret)

        # with nodes_list
        ret = common.query_nodes(api, nodes_list=[
            ['m3-1.grenoble.iot-lab.info'],
            ['a8-1.grenoble.iot-lab.info']], hostname='grenoble')
        self.assertEqual(['a8-1', 'm3-1'], ret)

        # exp_id and nodes_list
        ret = common.query_nodes(api, exp_id=123, nodes_list=[
            ['m3-1.lille.iot-lab.info'],
            ['wsn430-1.iot-lab.info']], hostname='lille')
        self.assertEqual(['wsn430-1'], ret)

    @patch('iotlabcli.get_user_credentials')
    @patch('iotlabcli.Api')
    @patch('iotlabaggregator.common.query_nodes')
    def test_get_nodes_selection(self, query_nodes, api, get_user):
        get_user.return_value = ('user', 'password')
        query_nodes.return_value = ['a8-1', 'm3-1']

        ret = common.get_nodes_selection(username=None, password=None,
                                         experiment_id=None, nodes_list=())
        self.assertEqual(['a8-1', 'm3-1'], ret)
        query_nodes.assert_called_with(api.return_value, None, ())

    @patch('iotlabcli.get_user_credentials')
    @patch('iotlabaggregator.common.query_nodes')
    def test_get_nodes_selection_http_error(self, query_nodes, get_user):
        get_user.return_value = ('user', 'password')
        query_nodes.side_effect = HTTPError('url', 401, 'Unauthorized',
                                            hdrs=None, fp=None)
        stderr = StringIO()
        with patch('sys.stderr', stderr):
            self.assertRaises(SystemExit, common.get_nodes_selection,
                              username=None, password=None,
                              experiment_id=None, nodes_list=())
        self.assertTrue('Register your login:password using `iotlab-auth`'
                        in stderr.getvalue())
