IoT-Lab Aggregation tools
=========================

[![CI](https://github.com/iot-lab/aggregation-tools/workflows/CI/badge.svg)](https://github.com/iot-lab/aggregation-tools/actions?query=workflow%3ACI+branch%3Amaster)
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
    ...


### From your computer ###

Outside the SSH frontends, `serial_aggregator` reaches the nodes of every
site of the experiment through the frontends: it starts one
`ssh -N -D` SOCKS proxy per site (your IoT-LAB login, from `iotlab-auth`,
and the SSH key of your IoT-LAB profile, which must work without a
prompt), connects to the nodes through them, and stops them at the end.
The nodes are then named `<node>.<site>`:

    you@yourpc $ serial_aggregator -i <exp_id>
    1795632001.112233;SOCKS proxy to grenoble on port 45227
    1795632001.554433;SOCKS proxy to saclay on port 53819
    1795632001.554500;Aggregator started
    1795632003.120000;m3-6.grenoble;> version
    1795632003.120100;m3-6.grenoble;2026.10
    1795632005.330000;m3-5.saclay;> version

`--socks <site>=<host>:<port>` uses a SOCKS5 proxy you already have for that
site (for example `ssh -f -N -D 1080 <login>@grenoble.iot-lab.info`) instead
of starting one. On a frontend of the experiment, nothing changes: the
nodes of that site, named without their site.

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

    # from your computer, nodes named <node>.<site>
    'm3-1.grenoble;message' -> sends 'message\n' to 'm3-1.grenoble'
    'm3,1-2.saclay;message' -> sends 'message\n' to 'm3-1.saclay', 'm3-2.saclay'
    'm3-1;message'          -> sends 'message\n' to the 'm3-1' of every site

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

Run it on your computer, it reaches the nodes of every site through the
frontends as the serial aggregator does (see "From your computer" above):

    you@yourpc $ sniffer_aggregator -i <exp_id> -o - | wireshark -k -i -

Or run it on the frontend and pipe its output:

    # Connect the output to your PC wireshark
    you@yourpc $ ssh <user>@<site> 'sniffer_aggregator -o -' | wireshark -k -i -

