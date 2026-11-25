Changelog
=========

Unreleased
----------

Features
~~~~~~~~

- serial_aggregator and sniffer_aggregator run on your computer: outside
  the SSH frontends, the nodes of every site are reached through an
  'ssh -D' SOCKS proxy to each frontend and named <node>.<site>;
  --socks <site>=<host>:<port> reuses an existing proxy
- serial input accepts '<node>.<site>;message'

2.1.1
-----

Features
~~~~~~~~

- Harmonize --id and --list options behaviour with cli-tools 

Bugs
~~~~

- Sniffer aggregator: fix negative timestamps

2.1.0
-----

Internal
~~~~~~~~

- Drop Python2 support

2.0.0
-----

Internal
~~~~~~~~

- Add Python3 support
- Switch the CI to Github Actions

