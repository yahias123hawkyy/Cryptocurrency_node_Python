from Peer import Peer
import constants as const
from message.msgexceptions import *
from jcs import canonicalize

import mempool
import objects
import peer_db

import asyncio
import ipaddress
import json
import random
import re
import sqlite3
import sys

PEERS = set()
CONNECTIONS = dict()
BACKGROUND_TASKS = set()
BLOCK_VERIFY_TASKS = dict()
BLOCK_WAIT_LOCK = None
TX_WAIT_LOCK = None
MEMPOOL = mempool.Mempool(const.GENESIS_BLOCK_ID, {})
LISTEN_CFG = {
        "address": const.ADDRESS,
        "port": const.PORT
}


def add_peer(peer):
    # Do not add banned peer addresses
    if peer.host in const.BANNED_HOSTS:
        return

    # Do not add loopback or multicast addrs
    try:
        ip = ipaddress.ip_address(peer.host)

        if ip.is_loopback or ip.is_multicast:
            return
    except:
        pass

    peer_db.store_peer(peer, PEERS)
    PEERS.add(peer)


def add_connection(peer, queue):
    ip, port = peer

    p = Peer(ip, port)
    if p in CONNECTIONS:
        raise Exception("Connection with {} already open!".format(peer))

    CONNECTIONS[p] = queue


def del_connection(peer):
    ip, port = peer
    del CONNECTIONS[Peer(ip, port)]


def mk_error_msg(error_str):
    return {"type": "error", "error": error_str}


def mk_hello_msg():
    return {"type": "hello", "version": const.VERSION, "agent": const.AGENT}


def mk_getpeers_msg():
    return {"type": "getpeers"}


def mk_peers_msg():
    pl = [f'{peer}' for peer in PEERS]
    return {"type": "peers", "peers": pl}


def mk_getobject_msg(objid):
    return {"type":"getobject", "objectid":objid}


def mk_object_msg(obj_dict):
    return {"type":"object", "object":obj_dict}


def mk_ihaveobject_msg(objid):
    return {"type":"ihaveobject", "objectid":objid}


def mk_chaintip_msg(blockid):
    return {"type":"chaintip", "blockid":blockid}


def mk_mempool_msg(txids):
    return {"type":"mempool", "txids":txids}


def mk_getchaintip_msg():
    return {"type": "getchaintip"}


def mk_getmempool_msg():
    return {"type": "getmempool"}


def parse_msg(msg_str):
    try:
        msg = json.loads(msg_str)
    except Exception as e:
        raise MsgParseException("JSON parse error: {}".format(str(e)))

    if not isinstance(msg, dict):
        raise MsgParseException("Malformed message!")
    if not 'type' in msg:
        raise MsgParseException("Malformed message!")
    if not isinstance(msg['type'], str):
        raise MsgParseException("Malformed message!")

    return msg


async def write_msg(writer, msg_dict):
    msg_bytes = canonicalize(msg_dict)
    writer.write(msg_bytes)
    writer.write(b'\n')
    await writer.drain()


def validate_allowed_keys(msg_dict, allowed_keys, msg_type):
    if len(set(msg_dict.keys()) - set(allowed_keys)) != 0:
        raise MalformedMsgException(
            "Message malformed: {} message contains invalid keys!".format(msg_type))


def validate_hello_msg(msg_dict):
    if msg_dict['type'] != 'hello':
        raise UnexpectedMsgException("Message type is not 'hello'!")

    try:
        if 'version' not in msg_dict:
            raise MalformedMsgException(
                "Message malformed: version is missing!")

        version = msg_dict['version']
        if not isinstance(version, str):
            raise MalformedMsgException(
                "Message malformed: version is not a string!")

        version_parts = version.split(".")
        if len(version_parts) != 3:
            raise MalformedMsgException(
                "Message malformed: version does not contain three parts!")

        if version_parts[0] != '0' or version_parts[1] != '8':
            raise MalformedMsgException(
                "Message malformed: version is not 0.8.x!")

        try:
            int(version_parts[2], 10)
        except:
            raise MalformedMsgException(
                "Message malformed: version is not 0.8.x!")

        validate_allowed_keys(msg_dict, ['type', 'version', 'agent'], 'hello')

    except MalformedMsgException as e:
        raise e
    except Exception as e:
        raise MalformedMsgException("Message malformed: {}".format(str(e)))


def validate_hostname(host_str):
    # Copied from here:
    # https://stackoverflow.com/questions/2532053/validate-a-hostname-string/2532344#2532344

    if len(host_str) > 255:
        return False
    if host_str[-1] == ".":
        host_str = host_str[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

    return all(allowed.match(x) for x in host_str.split("."))


def validate_ipv4addr(host_str):
    try:
        ip = ipaddress.IPv4Address(host_str)

    except:
        return False

    return True


def validate_ipv6addr(host_str):
    if host_str[0] != '[':
        return False
    if host_str[-1] != ']':
        return False

    try:
        ip = ipaddress.IPv6Address(host_str[1:-1])

    except:
        return False

    return True


def validate_peer_str(peer_str):
    peer_parts = peer_str.rsplit(':', 1)
    if len(peer_parts) != 2:
        return False

    host_str = peer_parts[0]
    port_str = peer_parts[1]

    port = 0
    try:
        port = int(port_str, 10)
    except:
        return False

    if port <= 0:
        return False

    if len(host_str) <= 0:
        return False

    if validate_hostname(host_str):
        return True
    if validate_ipv4addr(host_str):
        return True
    if validate_ipv6addr(host_str):
        return True

    return False


def validate_peers_msg(msg_dict):
    if msg_dict['type'] != 'peers':
        raise UnexpectedMsgException("Message type is not 'peers'!")

    try:
        if 'peers' not in msg_dict:
            raise MalformedMsgException("Message malformed: peers is missing!")

        peers = msg_dict['peers']
        if not isinstance(peers, list):
            raise MalformedMsgException(
                "Message malformed: peers is not a list!")

        validate_allowed_keys(msg_dict, ['type', 'peers'], 'peers')

        for p in peers:
            if not isinstance(p, str):
                raise MalformedMsgException(
                    "Message malformed: peer is not a string!")

            if not validate_peer_str(p):
                raise MalformedMsgException(
                    "Message malformed: malformed peer '{}'!".format(p))

    except MalformedMsgException as e:
        raise e
    except Exception as e:
        raise MalformedMsgException("Message malformed: {}".format(str(e)))


def validate_getpeers_msg(msg_dict):
    if msg_dict['type'] != 'getpeers':
        raise UnexpectedMsgException("Message type is not 'getpeers'!")

    validate_allowed_keys(msg_dict, ['type'], 'getpeers')


def validate_getchaintip_msg(msg_dict):
    if msg_dict['type'] != 'getchaintip':
        raise UnexpectedMsgException("Message type is not 'getchaintip'!")

    validate_allowed_keys(msg_dict, ['type'], 'getchaintip')


def validate_getmempool_msg(msg_dict):
    if msg_dict['type'] != 'getmempool':
        raise UnexpectedMsgException("Message type is not 'getmempool'!")

    validate_allowed_keys(msg_dict, ['type'], 'getmempool')


def validate_error_msg(msg_dict):
    if msg_dict['type'] != 'error':
        raise UnexpectedMsgException("Message type is not 'error'!")

    try:
        if 'error' not in msg_dict:
            raise MalformedMsgException("Message malformed: error is missing!")

        error = msg_dict['error']
        if not isinstance(error, str):
            raise MalformedMsgException(
                "Message malformed: error is not a string!")

        validate_allowed_keys(msg_dict, ['type', 'error'], 'error')

    except MalformedMsgException as e:
        raise e
    except Exception as e:
        raise MalformedMsgException("Message malformed: {}".format(str(e)))


def validate_ihaveobject_msg(msg_dict):
    if msg_dict['type'] != 'ihaveobject':
        raise UnexpectedMsgException("Message type is not 'ihaveobject'!")

    try:
        if 'objectid' not in msg_dict:
            raise MalformedMsgException("Message malformed: objectid is missing!")

        objectid = msg_dict['objectid']
        if not isinstance(objectid, str):
            raise MalformedMsgException(
                "Message malformed: objectid is not a string!")

        if not objects.validate_objectid(objectid):
            raise MalformedMsgException("Message malformed: objectid invalid!")

        validate_allowed_keys(msg_dict, ['type','objectid'], 'ihaveobject')

    except MalformedMsgException as e:
        raise e
    except Exception as e:
        raise MalformedMsgException("Message malformed: {}".format(str(e)))


def validate_getobject_msg(msg_dict):
    if msg_dict['type'] != 'getobject':
        raise UnexpectedMsgException("Message type is not 'getobject'!")

    try:
        if 'objectid' not in msg_dict:
            raise MalformedMsgException("Message malformed: objectid is missing!")

        objectid = msg_dict['objectid']
        if not isinstance(objectid, str):
            raise MalformedMsgException(
                "Message malformed: objectid is not a string!")

        if not objects.validate_objectid(objectid):
            raise MalformedMsgException("Message malformed: objectid invalid!")

        validate_allowed_keys(msg_dict, ['type','objectid'], 'getobject')

    except MalformedMsgException as e:
        raise e
    except Exception as e:
        raise MalformedMsgException("Message malformed: {}".format(str(e)))


def validate_object_msg(msg_dict):
    if msg_dict['type'] != 'object':
        raise UnexpectedMsgException("Message type is not 'object'!")

    try:
        if 'object' not in msg_dict:
            raise MalformedMsgException("Message malformed: object is missing!")

        obj = msg_dict['object']
        if not objects.validate_object(obj):
            raise MalformedMsgException(
                "Message malformed: malformed object!")

        validate_allowed_keys(msg_dict, ['type','object'], 'object')

    except MalformedMsgException as e:
        raise e
    except Exception as e:
        raise MalformedMsgException("Message malformed: {}".format(str(e)))


def validate_chaintip_msg(msg_dict):
    if msg_dict['type'] != 'chaintip':
        raise UnexpectedMsgException("Message type is not 'chaintip'!")

    try:
        if 'blockid' not in msg_dict:
            raise MalformedMsgException("Message malformed: blockid is missing!")

        blockid = msg_dict['blockid']
        if not isinstance(blockid, str):
            raise MalformedMsgException(
                "Message malformed: blockid is not a string!")

        if not objects.validate_objectid(blockid):
            raise MalformedMsgException("Message malformed: blockid invalid!")

        validate_allowed_keys(msg_dict, ['type','blockid'], 'chaintip')

    except MalformedMsgException as e:
        raise e
    except Exception as e:
        raise MalformedMsgException("Message malformed: {}".format(str(e)))


def validate_mempool_msg(msg_dict):
    if msg_dict['type'] != 'mempool':
        raise UnexpectedMsgException("Message type is not 'mempool'!")

    try:
        if 'txids' not in msg_dict:
            raise MalformedMsgException("Message malformed: txids is missing!")

        txids = msg_dict['txids']
        if not isinstance(txids, list):
            raise MalformedMsgException(
                "Message malformed: txids is not a list!")

        if not all(objects.validate_objectid(txid) for txid in txids):
            raise MalformedMsgException("Message malformed: txids invalid!")

        validate_allowed_keys(msg_dict, ['type','txids'], 'mempool')

    except MalformedMsgException as e:
        raise e
    except Exception as e:
        raise MalformedMsgException("Message malformed: {}".format(str(e)))


def validate_msg(msg_dict):
    msg_type = msg_dict['type']
    if msg_type == 'hello':
        validate_hello_msg(msg_dict)
    elif msg_type == 'getpeers':
        validate_getpeers_msg(msg_dict)
    elif msg_type == 'peers':
        validate_peers_msg(msg_dict)
    elif msg_type == 'getchaintip':
        validate_getchaintip_msg(msg_dict)
    elif msg_type == 'getmempool':
        validate_getmempool_msg(msg_dict)
    elif msg_type == 'error':
        validate_error_msg(msg_dict)
    elif msg_type == 'ihaveobject':
        validate_ihaveobject_msg(msg_dict)
    elif msg_type == 'getobject':
        validate_getobject_msg(msg_dict)
    elif msg_type == 'object':
        validate_object_msg(msg_dict)
    elif msg_type == 'chaintip':
        validate_chaintip_msg(msg_dict)
    elif msg_type == 'mempool':
        validate_mempool_msg(msg_dict)
    else:
        raise UnsupportedMsgException(
            "Message type {} not supported!".format(msg_type))


def handle_peers_msg(msg_dict):
    for p in msg_dict['peers']:
        peer_parts = p.rsplit(':', 1)

        host_str, port_str = peer_parts

        port = int(port_str, 10)

        peer = Peer(host_str, port)
        add_peer(peer)


def handle_error_msg(msg_dict, peer_self):
    print("{}: Received error '{}'".format(peer_self, msg_dict['error']))


async def handle_ihaveobject_msg(msg_dict, writer):
    objid = msg_dict['objectid']

    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (objid,))

        # already have object
        if not res.fetchone() is None:
            return
    finally:
        con.close()

    await write_msg(writer, mk_getobject_msg(objid))


async def handle_getobject_msg(msg_dict, writer):
    objid = msg_dict['objectid']
    obj_tuple = None

    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (objid,))

        obj_tuple = res.fetchone()
        # don't have object
        if obj_tuple is None:
            return
    finally:
        con.close()

    obj_dict = objects.expand_object(obj_tuple[0])

    await write_msg(writer, mk_object_msg(obj_dict))


def gather_previous_txs(db_cur, tx_dict):
    # coinbase transaction
    if 'height' in tx_dict:
        return {}

    # regular transaction
    prev_txs = {}
    for i in tx_dict['inputs']:
        ptxid = i['outpoint']['txid']

        res = db_cur.execute("SELECT obj FROM objects WHERE oid = ?", (ptxid,))
        first_res = res.fetchone()

        if not first_res is None:
            ptx_str = first_res[0]
            ptx_dict = objects.expand_object(ptx_str)

            if ptx_dict['type'] != 'transaction':
                continue

            prev_txs[ptxid] = ptx_dict

    return prev_txs


def get_block_utxo_height(blockid):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        # TODO: maybe collapse this into a single joined query

        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (blockid,))
        block_tuple = res.fetchone()
        if block_tuple is None:
            return (None, None, None)

        block = objects.expand_object(block_tuple[0])

        res = cur.execute("SELECT utxoset FROM utxo WHERE blockid = ?", (blockid,))
        utxo_tuple = res.fetchone()
        if utxo_tuple is None:
            return (block, None, None)

        utxo = objects.expand_object(utxo_tuple[0])

        res = cur.execute("SELECT height FROM heights WHERE blockid = ?", (blockid,))
        height_tuple = res.fetchone()
        if height_tuple is None:
            return (block, utxo, None)

        height = height_tuple[0]

        return (block, utxo, height)

    finally:
        con.close()


def get_block_txs(txids):
    txs = dict()

    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        for txid in txids:
            res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (txid,))
            tx_tuple = res.fetchone()
            if tx_tuple is not None:
                txs[txid] = objects.expand_object(tx_tuple[0])

        return txs

    finally:
        con.close()


def store_block_utxo_height(block, utxo, height: int):
    """
        Stores block its utxoset and height
    """
    blockid = objects.get_objid(block)

    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        block_str = objects.canonicalize(block).decode('utf-8')
        cur.execute("INSERT INTO objects VALUES(?, ?)", (blockid, block_str))

        utxo_str = objects.canonicalize(utxo).decode('utf-8')
        cur.execute("INSERT INTO utxo VALUES(?, ?)", (blockid, utxo_str))
        
        cur.execute("INSERT INTO heights VALUES(?, ?)", (blockid, height))

        con.commit()

    except asyncio.exceptions.CancelledError as e:
        con.rollback()
        raise e
    except Exception as e:
        con.rollback()
        raise e
    finally:
        con.close()


async def verify_block_task(block_dict):
    blockid = objects.get_objid(block_dict)

    prev_utxo = None
    prev_block = None
    prev_height = None

    previd = block_dict['previd']
    if previd is not None:
        # check if we have the previous block, fetch it if necessary
        prev_block, prev_utxo, prev_height = get_block_utxo_height(previd)
        i = 0
        while prev_block is None and i < const.BLOCK_VERIFY_WAIT_FOR_PREV_MUL:
            # already have task verifying the previous block
            if previd in BLOCK_VERIFY_TASKS:
                prev_cond = BLOCK_VERIFY_TASKS[previd][2]
                async with prev_cond:
                    await prev_cond.wait()
                prev_block, prev_utxo, prev_height = get_block_utxo_height(previd)
                break

            for q in CONNECTIONS.values():
                await q.put({"type":"needobject","objectid":previd})

            # let other tasks run
            async with BLOCK_WAIT_LOCK:
                try:
                    await asyncio.wait_for(BLOCK_WAIT_LOCK.wait(),
                            const.BLOCK_VERIFY_WAIT_FOR_PREV)
                except asyncio.exceptions.TimeoutError:
                    pass

            prev_block, prev_utxo, prev_height = get_block_utxo_height(previd)
            i = i + 1

        if prev_block is None:
            raise objects.BlockVerifyException("Previous block missing or invalid!")

    # check if we have all TXs, fetch them if necessary
    txs = get_block_txs(block_dict['txids'])
    missing_txids = set(block_dict['txids']) - set(txs.keys())
    i = 0
    while len(missing_txids) > 0 and i < const.BLOCK_VERIFY_WAIT_FOR_TXS_MUL:
        for q in CONNECTIONS.values():
            for mtxid in missing_txids:
                await q.put({"type":"needobject","objectid":mtxid})

        # let other tasks run
        async with TX_WAIT_LOCK:
            try:
                await asyncio.wait_for(TX_WAIT_LOCK.wait(),
                        const.BLOCK_VERIFY_WAIT_FOR_TXS)
            except asyncio.exceptions.TimeoutError:
                pass

        txs = get_block_txs(block_dict['txids'])
        missing_txids = set(block_dict['txids']) - set(txs.keys())
        i = i + 1

    if len(missing_txids) > 0:
        raise objects.BlockVerifyException("Timeout while waiting for TXs!")

    new_utxo, height = objects.verify_block_tail(block_dict, prev_block, prev_utxo,
            prev_height, txs)

    # if everything checks out store the block, its UTXO and its height and
    # broadcast the new block's ID to all connected peers.
    print("Adding new object '{}'".format(blockid))
    store_block_utxo_height(block_dict, new_utxo, height)

    # update mempool for new block
    new_chaintip = get_chaintip_blockid()
    MEMPOOL.rebase_to_block(new_chaintip)

    # notify other block verify tasks
    async with BLOCK_WAIT_LOCK:
        BLOCK_WAIT_LOCK.notify_all()

    for q in CONNECTIONS.values():
        await q.put({"type":"newobject","objectid":blockid})


def add_verify_block_task(objid, block, queue):
    if objid in BLOCK_VERIFY_TASKS:
        print("Already verifying block {}.".format(objid))
        BLOCK_VERIFY_TASKS[objid][1].add(queue)
        return

    print("Beginning verification of block {}.".format(objid))
    aw = verify_block_task(block)
    block_verify_task = asyncio.create_task(del_verify_block_task(aw, objid))
    BLOCK_VERIFY_TASKS[objid] = (block_verify_task, {queue}, asyncio.Condition())

async def del_verify_block_task(task, objid):
    err_str = None

    try:
        await task
        print("Verification of block {} successful.".format(objid))

    except objects.BlockVerifyException as e:
        print("Verification of block {} failed: {}".format(objid, str(e)))
        err_str = "Failed to verify block {}!".format(objid)
    except asyncio.exceptions.CancelledError:
        print("Verification of block {} failed: Cancelled".format(objid))
        err_str = "Failed to verify block {}!".format(objid)
    except asyncio.exceptions.TimeoutError:
        print("Verification of block {} failed: Timeout".format(objid))
        err_str = "Timeout while verifying block {}!".format(objid)
    except Exception as e:
        print("Verification of block {} failed: {}".format(objid, str(e)))
        err_str = "Failed to verify block {}!".format(objid)

    queues = BLOCK_VERIFY_TASKS[objid][1]
    cond = BLOCK_VERIFY_TASKS[objid][2]
    del BLOCK_VERIFY_TASKS[objid]

    if err_str:
        for queue in queues:
            try:
                queue.put_nowait({"type":"newerror","errormsg":err_str})
            except asyncio.QueueFull:
                print("Failed to send error msg for block {}!".format(objid))

    # notify other block verify tasks waiting for this one
    async with cond:
        cond.notify_all()

async def handle_object_msg(msg_dict, peer_self, writer):
    obj_dict = msg_dict['object']
    objid = objects.get_objid(obj_dict)

    ip_self, port_self = peer_self
    peer_self_obj = Peer(ip_self, port_self)

    err_str = None
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (objid,))

        # already have object
        if not res.fetchone() is None:
            # object has already been verified as it is in the DB
            if obj_dict['type'] == 'transaction':
                # add a transaction to the mempool if received
                if not MEMPOOL.try_add_tx(obj_dict):
                    print("Failed to add TX '{}' to the mempool.".format(objid))
            return

        print("Received new object '{}'".format(objid))

        if obj_dict['type'] == 'transaction':
            prev_txs = gather_previous_txs(cur, obj_dict)
            objects.verify_transaction(obj_dict, prev_txs)
        elif obj_dict['type'] == 'block':
            objects.verify_block(obj_dict)
            add_verify_block_task(objid, obj_dict, CONNECTIONS[peer_self_obj])
            return

        print("Adding new object '{}'".format(objid))

        obj_str = objects.canonicalize(obj_dict).decode('utf-8')
        cur.execute("INSERT INTO objects VALUES(?, ?)", (objid, obj_str))
        con.commit()
    except objects.TXVerifyException as e:
        con.rollback()
        print("Failed to verify TX '{}': {}".format(objid, str(e)))
        err_str = "Failed to verify transaction!"
    except objects.BlockVerifyException as e:
        con.rollback()
        print("Failed to verify block '{}': {}".format(objid, str(e)))
        err_str = "Failed to verify block!"
    except Exception as e:
        con.rollback()
        raise e
    finally:
        con.close()

    # if an error occurred send an error message
    if err_str:
        await write_msg(writer, mk_error_msg(err_str))
        return

    # try to add the new TX to the mempool
    if not MEMPOOL.try_add_tx(obj_dict):
        # TODO: check if this should lead to an error message
        print("Failed to add TX '{}' to the mempool.".format(objid))

    # notify block verify tasks
    async with TX_WAIT_LOCK:
        TX_WAIT_LOCK.notify_all()

    # gossip the new object to all other connections
    for k, q in CONNECTIONS.items():
        if k == peer_self_obj:
            continue
        await q.put({"type":"newobject","objectid":objid})


def get_chaintip_blockid():
    with sqlite3.connect(const.DB_NAME) as con:
        cur = con.cursor()
        res = cur.execute("SELECT blockid FROM heights ORDER BY height DESC LIMIT 1")

        blockid_tuple = res.fetchone()
        if blockid_tuple is None:
            return None

        return blockid_tuple[0]


async def handle_getchaintip_msg(msg_dict, writer):
    chain_head_blockid = get_chaintip_blockid()
    if chain_head_blockid is None:
        return

    await write_msg(writer, mk_chaintip_msg(chain_head_blockid))


async def handle_getmempool_msg(msg_dict, writer):
    await write_msg(writer, mk_mempool_msg(MEMPOOL.txs))


async def handle_chaintip_msg(msg_dict):
    blockid = msg_dict['blockid']

    with sqlite3.connect(const.DB_NAME) as con:
        cur = con.cursor()

        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (blockid,))

        # already have that chain
        if not res.fetchone() is None:
            return

    # ask all peers for the new block ID
    for q in CONNECTIONS.values():
        await q.put({"type":"needobject","objectid":blockid})


async def handle_mempool_msg(msg_dict):
    # ask all peers for the transactions in the mempool message
    for q in CONNECTIONS.values():
        for txid in msg_dict['txids']:
            await q.put({"type":"needobject","objectid":txid})


async def handle_queue_msg(msg_dict, writer):
    if msg_dict['type'] == 'newobject':
        await write_msg(writer, mk_ihaveobject_msg(msg_dict['objectid']))
    elif msg_dict['type'] == 'needobject':
        await write_msg(writer, mk_getobject_msg(msg_dict['objectid']))
    elif msg_dict['type'] == 'newerror':
        await write_msg(writer, mk_error_msg(msg_dict['errormsg']))


async def handle_connection(reader, writer):
    read_task = None
    queue_task = None

    peer = None
    queue = asyncio.Queue()
    try:
        peer = writer.get_extra_info('peername')
        if not peer:
            raise Exception("Failed to get peername!")

        add_connection(peer, queue)

        print("New connection with {}".format(peer))
    except Exception as e:
        print(str(e))
        try:
            writer.close()
        except:
            pass
        return

    try:
        await write_msg(writer, mk_hello_msg())
        await write_msg(writer, mk_getpeers_msg())
        await write_msg(writer, mk_getchaintip_msg())
        await write_msg(writer, mk_getmempool_msg())

        firstmsg_str = await asyncio.wait_for(reader.readline(),
                timeout=const.HELLO_MSG_TIMEOUT)
        firstmsg = parse_msg(firstmsg_str)
        validate_hello_msg(firstmsg)

        msg_str = None
        while True:
            if read_task is None:
                read_task = asyncio.create_task(reader.readline())
            if queue_task is None:
                queue_task = asyncio.create_task(queue.get())

            # wait for network or queue messages
            done, pending = await asyncio.wait([read_task, queue_task],
                    return_when = asyncio.FIRST_COMPLETED)
            if read_task in done:
                msg_str = read_task.result()
                read_task = None
            # handle queue messages
            if queue_task in done:
                queue_msg = queue_task.result()
                queue_task = None
                await handle_queue_msg(queue_msg, writer)
                queue.task_done()

            # if no message was received over the network continue
            if read_task is not None:
                continue

            msg = parse_msg(msg_str)
            validate_msg(msg)

            msg_type = msg['type']
            if msg_type == 'hello':
                raise UnexpectedMsgException("Additional handshake initiated by peer!")
            elif msg_type == 'getpeers':
                await write_msg(writer, mk_peers_msg())
            elif msg_type == 'peers':
                handle_peers_msg(msg)
            elif msg_type == 'error':
                handle_error_msg(msg, peer)
            elif msg_type == 'ihaveobject':
                await handle_ihaveobject_msg(msg, writer)
            elif msg_type == 'getobject':
                await handle_getobject_msg(msg, writer)
            elif msg_type == 'object':
                await handle_object_msg(msg, peer, writer)
            elif msg_type == 'getchaintip':
                await handle_getchaintip_msg(msg, writer)
            elif msg_type == 'chaintip':
                await handle_chaintip_msg(msg)
            elif msg_type == 'getmempool':
                await handle_getmempool_msg(msg, writer)
            elif msg_type == 'mempool':
                await handle_mempool_msg(msg)
            else:
                pass

    except asyncio.exceptions.TimeoutError:
        print("{}: Timeout".format(peer))
        try:
            await write_msg(writer, mk_error_msg("Timeout"))
        except:
            pass
    except MessageException as e:
        print("{}: {}".format(peer, str(e)))
        try:
            await write_msg(writer, mk_error_msg(e.NETWORK_ERROR_MESSAGE))
        except:
            pass
    except Exception as e:
        print("{}: {}".format(peer, str(e)))
    finally:
        print("Closing connection with {}".format(peer))
        writer.close()
        del_connection(peer)
        if read_task is not None and not read_task.done():
            read_task.cancel()
        if queue_task is not None and not queue_task.done():
            queue_task.cancel()


async def connect_to_node(peer: Peer):
    try:
        reader, writer = await asyncio.open_connection(peer.host, peer.port,
                limit=const.RECV_BUFFER_LIMIT)
    except Exception as e:
        print(str(e))
        return

    await handle_connection(reader, writer)


async def listen():
    server = await asyncio.start_server(handle_connection, LISTEN_CFG['address'],
            LISTEN_CFG['port'], limit=const.RECV_BUFFER_LIMIT)

    print("Listening on {}:{}".format(LISTEN_CFG['address'], LISTEN_CFG['port']))

    async with server:
        await server.serve_forever()


async def bootstrap():
    for p in const.PRELOADED_PEERS:
        add_peer(p)
        t = asyncio.create_task(connect_to_node(p))
        BACKGROUND_TASKS.add(t)
        t.add_done_callback(BACKGROUND_TASKS.discard)


def resupply_connections():
    cons = set(CONNECTIONS.keys())

    if len(cons) >= const.LOW_CONNECTION_THRESHOLD:
        return

    npeers = const.LOW_CONNECTION_THRESHOLD - len(cons)
    available_peers = PEERS - cons

    if len(available_peers) == 0:
        print("Not enough peers available to reconnect.")
        return

    if len(available_peers) < npeers:
        npeers = len(available_peers)

    print("Connecting to {} new peers.".format(npeers))

    chosen_peers = random.sample(tuple(available_peers), npeers)
    for p in chosen_peers:
        t = asyncio.create_task(connect_to_node(p))
        BACKGROUND_TASKS.add(t)
        t.add_done_callback(BACKGROUND_TASKS.discard)


async def init():
    global BLOCK_WAIT_LOCK
    BLOCK_WAIT_LOCK = asyncio.Condition()
    global TX_WAIT_LOCK
    TX_WAIT_LOCK = asyncio.Condition()

    PEERS.update(peer_db.load_peers())

    bootstrap_task = asyncio.create_task(bootstrap())
    listen_task = asyncio.create_task(listen())

    # Service loop
    while True:
        print("Service loop reporting in.")
        print("Open connections: {}".format(set(CONNECTIONS.keys())))

        # Open more connections if necessary
        resupply_connections()

        await asyncio.sleep(const.SERVICE_LOOP_DELAY)

    await bootstrap_task
    await listen_task


def main():
    asyncio.run(init())


if __name__ == "__main__":
    if len(sys.argv) == 3:
        LISTEN_CFG['address'] = sys.argv[1]
        LISTEN_CFG['port'] = sys.argv[2]

    main()
