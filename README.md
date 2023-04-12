# CryptoCurrency

First create the database by running `python3 create_db.py`.

Then run the node with `python3 main.py`.

At least Python 3.9 and the packages `cryptography` 3.4.8 and `jcs` 0.2.1 are
required. You can install the required packages by running `pip install -r
requirements.txt`.

The script `run.sh` will install the required packages using pip, then create
the database if it doesn't already exist and then run the node on
`127.0.0.1:18018`. When using the `run.sh` script the node will therefore only
listen on localhost.

At startup the node attempts to connect to the peers in `PRELOADED_PEERS` in
`constants.py`. It will also start listening on the port `PORT`.

Learned peers are stored in the `peers.csv` file. This file is read on startup.
Localhost and multicast addresses are never added as peers.

Every `SERVICE_LOOP_DELAY` seconds the so called service loop runs. Currently,
this is where the number of active connections is checked and new connections
are established as needed. If the number of active connections drops below
`LOW_CONNECTION_THRESHOLD`, the node will attempt to establish new connections
to randomly selected peers that it learned previously.

Upon establishing a connection the node sends a hello and then a getpeers
message. It will wait `HELLO_MSG_TIMEOUT` seconds for a hello message before
closing the connections. After receiving a hello message, the connection will
remain open until an error occurs or until the peer closes it. If an error
message is received the connection is closed as well.

The `BANNED_HOSTS` list contains IP addresses of hosts that should never be
learned as peers. Currently it includes some public DNS servers and addresses
that seemed to belong to client machines that were inadvertedly added by some
peer. We identified these client machines by determining that their IPs showed
up with a large number of different ports in a received peers message and were
not listed in the IP database in TUWEL.

The IP `20.23.212.159` is not a client IP, as it is listed in the IP database
in TUWEL. Nevertheless, we blacklisted it, as some peers distributed this
address with dozens of different ports, making the peer list extremely large. A
related post in TUWEL is here:
https://tuwel.tuwien.ac.at/mod/forum/discuss.php?d=337348

Furthermore, the IP addresses `164.92.143.182`, `20.126.29.4`, `142.93.167.83`
and `88.200.23.239` are also not client IPs and are listed in the IP database.
However, these IPs showed up with hundreds and in some cases thousands of
ports. We blacklisted them to keep the peers list manageable.

We suspect, that the issue with some IP addresses showing up with a large
number of ports is due to a node adding incoming connections (which use
ephemeral ports on the client side) to the list of peers it then distributes.
We think this is invalid, as it is not possible to connect back to those ports.

We have included the `.git` folder in our submission, so that you can determine
who wrote which code.
