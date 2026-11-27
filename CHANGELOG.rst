Changelog
=========

2.3.0
-----

Features
~~~~~~~~

- serial_aggregator and sniffer_aggregator run on your computer: outside
  the SSH frontends, the nodes of every site are reached through an
  'ssh -D' SOCKS proxy to each frontend and named <node>.<site>;
  --socks <site>=<host>:<port> reuses an existing proxy
- serial input accepts '<node>.<site>;message'

Bugs
~~~~

- serial_aggregator and sniffer_aggregator exit when the experiment stops:
  the end of a node connection was not seen, the aggregator read it in a
  loop (one CPU core busy) and never exited
- no 'Bad file descriptor' errors at the exit: the sockets are closed once
  the reading thread has ended
- a node unreachable at the start no longer keeps the aggregator running

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

