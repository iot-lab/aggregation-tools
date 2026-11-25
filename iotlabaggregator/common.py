#! /usr/bin/env python

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


"""Common functions that may be required"""

import itertools
import os

import iotlabcli
import iotlabcli.parser.common
import iotlabcli.parser.node
from iotlabcli import experiment

import iotlabaggregator
from iotlabaggregator import socksproxy

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
        {'network_address': 'a8-1.strasbourg.iot-lab.info',\
         'site': 'strasbourg'},\
        {'network_address': 'a8-1.grenoble.iot-lab.info', 'site': 'grenoble'},\
        ]}

    >>> extract_nodes(resources, hostname='grenoble')
    ['m3-1', 'a8-1']
    """
    hostname = hostname or HOSTNAME
    sites_nodes = [n for n in resources["items"] if n["site"] == hostname]
    nodes = [n["network_address"].split(".")[0] for n in sites_nodes]
    return nodes


def extract_remote_nodes(resources):
    """Extract the nodes of every site, named <node>.<site>.

    >>> resources = {"items": [ \
        {'network_address': 'm3-1.grenoble.iot-lab.info', 'site': 'grenoble'},\
        {'network_address': 'a8-1.strasbourg.iot-lab.info',\
         'site': 'strasbourg'},\
        ]}
    >>> extract_remote_nodes(resources)
    ['m3-1.grenoble', 'a8-1.strasbourg']
    """
    return [".".join(n["network_address"].split(".")[:2]) for n in resources["items"]]


def is_frontend(resources, hostname=None):
    """Tell whether this host is the SSH frontend of a site of ``resources``.

    >>> resources = {"items": [{'network_address': 'm3-1.grenoble.iot-lab.info',
    ...                         'site': 'grenoble'}]}
    >>> is_frontend(resources, 'grenoble'), is_frontend(resources, 'laptop')
    (True, False)
    """
    hostname = hostname or HOSTNAME
    return any(n["site"] == hostname for n in resources["items"])


def query_nodes(api, exp_id=None, nodes_list=None, hostname=None):
    """Get nodes list from nodes_list or current running experiment.

    On a frontend, the nodes of its site (``m3-1``); elsewhere, the nodes of
    every site, named ``m3-1.grenoble`` and reached through the frontends.
    """
    hostname = hostname or HOSTNAME
    nodes_list = nodes_list or []
    # -l grenoble,m3,1 -l grenoble,m3,5
    # [['m3-1.grenoble.iot-lab.info'], ['m3-5.grenoble.iot-lab.info']]
    nodes_list = frozenset(itertools.chain.from_iterable(nodes_list))
    # try to get currently running experiment
    if exp_id is None:
        exp_id = iotlabcli.get_current_experiment(api)
    exp_nodes = experiment.get_experiment(api, exp_id, "nodes")
    if not is_frontend(exp_nodes, hostname):
        exp_nodes_list = extract_remote_nodes(exp_nodes)
        selected = {".".join(n.split(".")[:2]) for n in nodes_list}
        nodes = set(exp_nodes_list).intersection(selected)
        return sorted(nodes or exp_nodes_list)
    nodes_list = [n.split(".")[0] for n in nodes_list if hostname in n]
    exp_nodes_list = extract_nodes(exp_nodes, hostname)
    nodes = set(exp_nodes_list).intersection(nodes_list)
    if nodes:
        return sorted(list(nodes))
    return sorted(exp_nodes_list)


def add_nodes_selection_parser(parser):
    """Add parser arguments for selecting nodes"""

    iotlabcli.parser.common.add_auth_arguments(parser)
    parser.add_argument(
        "-v", "--version", action="version", version=iotlabaggregator.__version__
    )
    nodes_group = parser.add_argument_group(
        description="By default, select currently running experiment nodes",
        title="Nodes selection",
    )

    nodes_group.add_argument(
        "-i", "--id", dest="experiment_id", type=int, help="experiment id submission"
    )
    nodes_group.add_argument(
        "-l",
        "--list",
        action="append",
        type=iotlabcli.parser.common.nodes_list_from_str,
        dest="nodes_list",
        help="nodes list",
    )
    remote_group = parser.add_argument_group(
        title="Outside the SSH frontends",
        description=(
            "Elsewhere than on a frontend of the experiment sites, the nodes "
            "of every site are reached through an 'ssh -D' SOCKS proxy to each "
            "frontend (IoT-LAB login and SSH key), and named <node>.<site>"
        ),
    )
    remote_group.add_argument(
        "--socks",
        action="append",
        type=socksproxy.parse_socks_option,
        metavar="SITE=HOST:PORT",
        default=[],
        help="use this SOCKS5 proxy for the site instead of starting one",
    )


def get_nodes_selection(
    username, password, experiment_id, nodes_list, *_args, **_kwargs
):  # pylint:disable=unused-argument
    """Return the requested nodes from 'experiment_id', and 'nodes_list"""
    username, password = iotlabcli.get_user_credentials(username, password)
    api = iotlabcli.Api(username, password)
    with iotlabcli.parser.common.catch_missing_auth_cli():
        nodes = query_nodes(api, experiment_id, nodes_list)
    return nodes


def iotlab_login(username=None):
    """Return the IoT-LAB login: given, or from the credentials file."""
    if username:
        return username
    login, _ = iotlabcli.get_user_credentials()
    if not login:
        raise RuntimeError("no IoT-LAB login: run 'iotlab-auth -u <login>' or use -u")
    return login


def nodes_proxies(nodes_list, username=None, socks=()):
    """Context manager of the SOCKS proxies the nodes need, per site.

    Empty for the nodes of a frontend, named without a site.
    """
    sites = sorted({n.split(".", 1)[1] for n in nodes_list if "." in n})
    if not sites:
        return socksproxy.frontend_proxies([], "")
    return socksproxy.frontend_proxies(sites, iotlab_login(username), dict(socks))
