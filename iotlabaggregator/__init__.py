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

""" Aggregator tools for IoT-Lab platform """

import sys
import logging

__version__ = '2.1.1'


# Use loggers for all outputs to have the same config
LOG_FMT = logging.Formatter("%(created)f;%(message)s")

# error logger
LOGGER = logging.getLogger('iotlabaggregator')
_LOGGER = logging.StreamHandler(sys.stderr)
_LOGGER.setFormatter(LOG_FMT)
LOGGER.setLevel(logging.INFO)
LOGGER.addHandler(_LOGGER)
