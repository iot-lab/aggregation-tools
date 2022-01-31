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


""" Common functions that may be required """
import os
import itertools
import iotlabcli
from iotlabcli import experiment
import iotlabcli.parser.common
import iotlabcli.parser.node

import iotlabaggregator

HOSTNAME = os.uname()[1]


# http://stackoverflow.com/questions/1092531/event-system-in-python
class Event(list):  # pylint:disable=too-few-public-methods
    """Event subscription.

    A list of callable objects. Calling an instance of this will cause a
    call to each item in the list in ascending order by index.

    Example Usage:
    >>> def f(x):
    ...     print('f(%s)' % x)
    >>> def g(x):
    ...     print('g(%s)' % x)

    >>> e = Event()
    >>> e()
    >>> e.append(f)
    >>> e(123)
    f(123)
    >>> e.remove(f)
    >>> e()

    >>> e += (f, g)
    >>> e(10)
    f(10)
    g(10)
    >>> del e[0]
    >>> e(2)
    g(2)


    >>> e   # doctest: +ELLIPSIS
    Event('[<function g at 0x...>]')

    """

    def __call__(self, *args, **kwargs):
        for func in self:
            func(*args, **kwargs)

    def __repr__(self):
        return f"Event({list.__repr__(self)!r})"


def extract_nodes(resources, hostname=None):
    """ Extract the nodes for this server
    >>> resources = {"items": [ \
        {'network_address': 'm3-1.grenoble.iot-lab.info', 'site': 'grenoble'},\
        {'network_address': 'wsn430-1.lille.iot-lab.info', 'site': 'lille'},\
        {'network_address': 'a8-1.strasbourg.iot-lab.info',\
         'site': 'strasbourg'},\
        {'network_address': 'wsn430-4.grenoble.iot-lab.info', 'site':\
         'grenoble'},\
        {'network_address': 'a8-1.grenoble.iot-lab.info', 'site': 'grenoble'},\
        ]}

    >>> extract_nodes(resources, hostname='grenoble')
    ['m3-1', 'wsn430-4', 'a8-1']
    """
    hostname = hostname or HOSTNAME
    sites_nodes = [n for n in resources['items'] if n['site'] == hostname]
    nodes = [n['network_address'].split('.')[0] for n in sites_nodes]
    return nodes


def query_nodes(api, exp_id=None, nodes_list=None, hostname=None):
    """Get nodes list from nodes_list or current running experiment."""
    hostname = hostname or HOSTNAME
    nodes_list = nodes_list or []
    # -l grenoble,m3,1 -l grenoble,m3,5
    # [['m3-1.grenoble.iot-lab.info'], ['m3-5.grenoble.iot-lab.info']]
    nodes_list = frozenset(itertools.chain.from_iterable(nodes_list))
    nodes_list = [n.split('.')[0] for n in nodes_list if hostname in n]
    # try to get currently running experiment
    if exp_id is None:
        exp_id = iotlabcli.get_current_experiment(api)
    exp_nodes = experiment.get_experiment(api, exp_id, 'nodes')
    exp_nodes_list = extract_nodes(exp_nodes, hostname)
    nodes = set(exp_nodes_list).intersection(nodes_list)
    if nodes:
        return sorted(list(nodes))
    return sorted(exp_nodes_list)


def add_nodes_selection_parser(parser):
    """ Add parser arguments for selecting nodes """

    iotlabcli.parser.common.add_auth_arguments(parser)
    parser.add_argument('-v', '--version', action='version',
                        version=iotlabaggregator.__version__)
    nodes_group = parser.add_argument_group(
        description="By default, select currently running experiment nodes",
        title="Nodes selection")

    nodes_group.add_argument('-i', '--id', dest='experiment_id', type=int,
                             help='experiment id submission')
    nodes_group.add_argument('-l', '--list', action='append',
                             type=iotlabcli.parser.common.nodes_list_from_str,
                             dest='nodes_list', help='nodes list')


def get_nodes_selection(username, password, experiment_id, nodes_list,
                        *_args, **_kwargs):  # pylint:disable=unused-argument
    """ Return the requested nodes from 'experiment_id', and 'nodes_list """
    username, password = iotlabcli.get_user_credentials(username, password)
    api = iotlabcli.Api(username, password)
    with iotlabcli.parser.common.catch_missing_auth_cli():
        nodes = query_nodes(api, experiment_id, nodes_list)
    return nodes
