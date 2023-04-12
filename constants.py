from Peer import Peer


PORT = 18018
ADDRESS = "0.0.0.0"
SERVICE_LOOP_DELAY = 10
VERSION = '0.8.4'
AGENT = 'Snekel'
LOW_CONNECTION_THRESHOLD = 3
HELLO_MSG_TIMEOUT = 10.0
DB_NAME = 'snekel.db'
RECV_BUFFER_LIMIT = 512 * 1024
BLOCK_TARGET = "00000002af000000000000000000000000000000000000000000000000000000"
BLOCK_VERIFY_WAIT_FOR_PREV_MUL = 10
BLOCK_VERIFY_WAIT_FOR_PREV = 1
BLOCK_VERIFY_WAIT_FOR_TXS_MUL = 10
BLOCK_VERIFY_WAIT_FOR_TXS = 1
BLOCK_REWARD = 50_000_000_000_000
GENESIS_BLOCK_ID = "00000000a420b7cefa2b7730243316921ed59ffe836e111ca3801f82a4f5360e"
GENESIS_BLOCK = {
        "created":1624219079,
        "miner":"dionyziz",
        "nonce":"0000000000000000000000000000000000000000000000000000002634878840",
        "note":"The Economist 2021-06-20: Crypto-miners are probably to blame for the graphics-chip shortage",
        "previd":None,
        "txids":[],
        "type":"block",
        "T":"00000002af000000000000000000000000000000000000000000000000000000",
}


BANNED_HOSTS = [
        "1.1.1.1",
        "8.8.8.8",
        "20.23.212.159", # excessive ports, see TUWEL
        "84.115.238.131", # excessive ports
        "85.127.44.22", # excessive ports
        "84.113.55.218", # excessive ports
        "84.113.167.151", # excessive ports
        "157.230.31.236", # excessive ports
        "178.191.208.59", # excessive ports
        "84.115.221.58", # excessive ports
        "62.99.145.254", # excessive ports
        "91.113.41.50", # excessive ports
        "80.108.106.200", # excessive ports
        "91.118.114.136", # excessive ports
        "164.92.143.182", # excessive ports, is in IP DB but has 3143 ports!
        "128.130.246.129", # excessive ports
        "84.115.223.186", # excessive ports
        "84.115.238.55", # excessive ports
        "20.126.29.4", # excessive ports, is in IP DB but has 248 ports!
        "128.130.112.83", # excessive ports
        "167.71.36.88", # excessive ports
        "157.230.99.2", # excessive ports
        "142.93.167.83", # excessive ports, is in IP DB but has 3744 ports!
        "128.130.239.199", # excessive ports
        "84.115.210.138", # excessive ports
        "84.115.217.219", # excessive ports
        "88.200.23.239", # excessive ports, is in IP DB but has 942 ports!
        "86.56.242.179", # excessive ports
        "45.156.242.189", # excessive ports
        "62.178.51.126", # excessive ports
        "89.144.203.14", # excessive ports
        "62.178.13.17", # excessive ports
        "89.142.138.94", # excessive ports
        "84.115.239.208", # excessive ports
]

PRELOADED_PEERS = {
    Peer("128.130.122.101", 18018), # lecturers node
    Peer("20.123.80.80", 18018),
    Peer("143.244.205.208", 18018),
    Peer("138.197.177.229", 18018),
    Peer("46.101.71.58", 18018),
    Peer("51.137.60.68", 18018),
}
