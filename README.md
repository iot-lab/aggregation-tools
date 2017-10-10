IoT-Lab Aggregation tools
=========================

[![Build Status](https://travis-ci.org/iot-lab/aggregation-tools.svg?branch=master)](https://travis-ci.org/iot-lab/aggregation-tools)
[![codecov](https://codecov.io/gh/iot-lab/aggregation-tools/branch/master/graph/badge.svg)](https://codecov.io/gh/iot-lab/aggregation-tools)

Tools that allow aggregating data results from many nodes at a time.
It connects to several tcp connections and handle the received data.

IoT-LAB aggregation-tools, including all examples, code snippets and attached
documentation is covered by the CeCILL v2.1 free software licence.


Serial aggregator
-----------------

Aggregate all the serial links of an experiment and print it to stdout.

### Usage ###

    $ serial_aggregator [-i <exp_id>] [-l nodes_list|-l ...]
    1395240359.168975;Aggregator started
    1395240359.286712;m3-46; Type Enter to stop printing this help
    1395240359.286853;m3-46;
    1395240359.292523;m3-9;
    1395240359.292675;m3-9;IoT-Lab Simple Demo program
    1395240359.292820;m3-9;Type command
    1395240359.293094;m3-9;    h:  print this help
    1395240359.293241;m3-9;    t:  temperature measure
    1395240359.293612;m3-9;    l:  luminosity measure
    1395240359.293760;m3-9;    s:  send a radio packet
    1395240359.294044;m3-9;
    1395240359.294212;m3-9; Type Enter to stop printing this help
    1395240359.294781;wsn430-37;
    1395240359.294949;wsn430-37;Senslab Simple Demo program
    1395240359.295098;wsn430-37;Type command
    ...


### Sending messages ###

Standard input is parsed to allow sending messages to the nodes.
It's read using 'readline' and so you get a shell-like feeling.

Parsing is done using the function `extract_nodes_and_message(line)` see the
docstring for all allowed values.

### Examples ###

    ''    -> does not send anything to anyone, allows 'blanking' lines

    ' '   -> sends   ' \n' to all nodes
    'msg' -> sends 'msg\n' to all nodes

    'm3,1-3+5;message'  -> sends 'message\n' to nodes 'm3-[1, 2, 3, 5]'
    'm3-1;message'      -> sends 'message\n' to nodes 'm3-1'

    'csv;message;with;semicolons' -> sends 'csv;message;with;semicolons' to all
                                     nodes as 'csv;' is not a valid
                                     node identifier


Sniffer aggregator
------------------

Aggregate all the gateways sniffer into a pcap formatted file.

The gateways sniffer generate 'ZEP' encapsulated data:
<https://www.wireshark.org/docs/dfref/z/zep.html>

ZEP packets are saved in a pcap file encapsulated as a Ethernet-IP-UDP packet
send to port 17754 <http://wiki.wireshark.org/IEEE_802.15.4>.


### Usage ###

#### From the ssh frontend ####

Basic usage from the ssh fronted

    $ sniffer_aggregator [-i <exp_id>] [-l nodes_list|-l ...] <-o pcap_file>

    # save current experiment output to a file
    $ sniffer_aggregator -o radio_experiment.pcap
    1420464895.805985;Aggregator started


#### From your computer ####

Connecting to your computer wireshark using pipes

    # Connect the output to your PC wireshark
    you@yourpc $ ssh <user>@<site> 'sniffer_aggregator -o -' | wireshark -k -i -

