import copy
import sqlite3

import constants as const
import objects

def fetch_object(oid, cur):
    res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (oid,))
    obj_tuple = res.fetchone()
    if obj_tuple is None:
        raise Exception('Cannot find object {}!'.format(oid))
    return objects.expand_object(obj_tuple[0])

def fetch_utxo(bid, cur):
    res = cur.execute("SELECT utxoset FROM utxo WHERE blockid = ?", (bid,))
    utxo_tuple = res.fetchone()
    if utxo_tuple is None:
        raise Exception('Cannot find UTXO for {}!'.format(bid))
    return objects.expand_object(utxo_tuple[0])

def find_lca_and_intermediate_blocks(tip, blockids):
    block = None
    blockid = None
    inter_blocks = []
    with sqlite3.connect(const.DB_NAME) as con:
        cur = con.cursor()

        while True:
            block = fetch_object(tip, cur)
            blockid = objects.get_objid(block)
            inter_blocks.append(block)

            if blockid in blockids:
                break

            tip = block['previd']

    return blockid, inter_blocks

def find_all_txs(txids):
    txs = []
    with sqlite3.connect(const.DB_NAME) as con:
        cur = con.cursor()

        for txid in txids:
            tx = fetch_object(txid, cur)
            txs.append(tx)

    return txs

def get_all_txids_in_blocks(blocks):
    txids = []
    for b in blocks:
        txids.extend(b['txids'])

    return txids

def get_lca_and_intermediate_blocks(old_tip: str, new_tip: str):
    _, old_blocks = find_lca_and_intermediate_blocks(old_tip, [const.GENESIS_BLOCK_ID])
    old_blockids = [objects.get_objid(b) for b in old_blocks]
    lcaid, new_blocks = find_lca_and_intermediate_blocks(new_tip, old_blockids)

    new_old_blocks = []
    for old_block in old_blocks:
        if objects.get_objid(old_block) == lcaid:
            break

        new_old_blocks.append(old_block)

    return lcaid, new_old_blocks, new_blocks[:-1]

def rebase_mempool(old_tip: str, new_tip: str, mptxids: list[str]):
    lcaid, old_blocks, new_blocks = get_lca_and_intermediate_blocks(old_tip, new_tip)

    old_txids = get_all_txids_in_blocks(reversed(old_blocks)) + mptxids
    new_txids = get_all_txids_in_blocks(reversed(new_blocks))

    old_txs = find_all_txs(old_txids)

    utxo = None
    with sqlite3.connect(const.DB_NAME) as con:
        cur = con.cursor()

        # get UTXO from latest block in the new subchain
        bid = lcaid
        if len(new_blocks) > 0:
            bid = objects.get_objid(new_blocks[0])

        utxo = fetch_utxo(bid, cur)

    new_mptxids = []
    for txid, tx in zip(old_txids, old_txs):
        # skip transactions that are already in the new subchain
        if txid in new_txids:
            continue

        # skip coinbase transactions
        if 'height' in tx:
            continue

        # skip transactions that don't apply to the UTXO
        nutxo = copy.deepcopy(utxo)
        try:
            objects.update_utxo_and_calculate_fee(tx, nutxo)
        except objects.BlockVerifyException:
            continue

        utxo = nutxo
        new_mptxids.append(txid)

    return utxo, new_mptxids

class Mempool:
    def __init__(self, bbid: str, butxo: dict):
        self.base_block_id = bbid
        self.utxo = butxo
        self.txs = []

    def try_add_tx(self, tx: dict) -> bool:
        # never add a coinbase to the mempool
        if 'height' in tx:
            return True

        txid = objects.get_objid(tx)
        # This check is probably not strictly necessary as the UTXO would
        # already be consumed if the same TX is added again.
        if txid in self.txs:
            return False

        nutxo = copy.deepcopy(self.utxo)
        try:
            objects.update_utxo_and_calculate_fee(tx, nutxo)
        except objects.BlockVerifyException:
            return False

        self.utxo = nutxo
        self.txs.append(txid)
        return True

    def rebase_to_block(self, bid: str):
        if self.base_block_id == bid:
            return

        nutxo, nmp = rebase_mempool(self.base_block_id, bid, self.txs)

        self.utxo = nutxo
        self.base_block_id = bid
        self.txs = nmp
