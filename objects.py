from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import copy
import hashlib
import json
import re

import constants as const

OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_objectid(objid_str):
    if not isinstance(objid_str, str):
        return False
    return OBJECTID_REGEX.match(objid_str)

PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    if not isinstance(pubkey_str, str):
        return False
    return PUBKEY_REGEX.match(pubkey_str)

SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
def validate_signature(sig_str):
    if not isinstance(sig_str, str):
        return False
    return SIGNATURE_REGEX.match(sig_str)

NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    if not isinstance(nonce_str, str):
        return False
    return NONCE_REGEX.match(nonce_str)

TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    if not isinstance(target_str, str):
        return False
    return TARGET_REGEX.match(target_str)

def validate_transaction_input(in_dict):
    if not isinstance(in_dict, dict):
        return False

    if 'sig' not in in_dict:
        return False
    if not isinstance(in_dict['sig'], str):
        return False
    if not validate_signature(in_dict['sig']):
        return False

    if 'outpoint' not in in_dict:
        return False
    if not isinstance(in_dict['outpoint'], dict):
        return False

    outpoint = in_dict['outpoint']
    if 'txid' not in outpoint:
        return False
    if not isinstance(outpoint['txid'], str):
        return False
    if not validate_objectid(outpoint['txid']):
        return False
    if 'index' not in outpoint:
        return False
    if not isinstance(outpoint['index'], int):
        return False
    if outpoint['index'] < 0:
        return False
    if len(set(outpoint.keys()) - set(['txid', 'index'])) != 0:
        return False

    if len(set(in_dict.keys()) - set(['sig', 'outpoint'])) != 0:
        return False

    return True

def validate_transaction_output(out_dict):
    if not isinstance(out_dict, dict):
        return False

    if 'pubkey' not in out_dict:
        return False
    if not isinstance(out_dict['pubkey'], str):
        return False
    if not validate_pubkey(out_dict['pubkey']):
        return False

    if 'value' not in out_dict:
        return False
    if not isinstance(out_dict['value'], int):
        return False
    if out_dict['value'] < 0:
        return False

    if len(set(out_dict.keys()) - set(['pubkey', 'value'])) != 0:
        return False

    return True

def validate_transaction(trans_dict):
    if not isinstance(trans_dict, dict):
        return False

    if 'type' not in trans_dict:
        return False
    if not isinstance(trans_dict['type'], str):
        return False
    if not trans_dict['type'] == 'transaction':
        return False

    if 'outputs' not in trans_dict:
        return False
    if not isinstance(trans_dict['outputs'], list):
        return False
    if not all(validate_transaction_output(o) for o in trans_dict['outputs']):
        return False
    if len(trans_dict['outputs']) == 0:
        return False

    # coinbase transaction
    if 'height' in trans_dict:
        if not isinstance(trans_dict['height'], int):
            return False
        if trans_dict['height'] < 0:
            return False

        if len(trans_dict['outputs']) > 1:
            return False

        if len(set(trans_dict.keys()) - set(['type', 'height', 'outputs'])) != 0:
            return False

        return True

    # regular transaction
    elif 'inputs' in trans_dict:
        if not isinstance(trans_dict['inputs'], list):
            return False
        if not all(validate_transaction_input(i) for i in trans_dict['inputs']):
            return False
        if len(trans_dict['inputs']) == 0:
            return False

        if len(set(trans_dict.keys()) - set(['type', 'inputs', 'outputs'])) != 0:
            return False

        return True

    return False

def validate_block(block_dict):
    if not isinstance(block_dict, dict):
        return False

    if 'type' not in block_dict:
        return False
    if not isinstance(block_dict['type'], str):
        return False
    if not block_dict['type'] == 'block':
        return False

    if 'txids' not in block_dict:
        return False
    if not isinstance(block_dict['txids'], list):
        return False
    if not all(validate_objectid(t) for t in block_dict['txids']):
        return False

    if 'nonce' not in block_dict:
        return False
    if not isinstance(block_dict['nonce'], str):
        return False
    if not validate_nonce(block_dict['nonce']):
        return False

    if 'previd' not in block_dict:
        return False
    if block_dict['previd'] is not None:
        if not isinstance(block_dict['previd'], str):
            return False
        if not validate_objectid(block_dict['previd']):
            return False

    if 'created' not in block_dict:
        return False
    if not isinstance(block_dict['created'], int):
        return False
    try:
        datetime.utcfromtimestamp(block_dict['created'])
    except Exception:
        return False

    if 'T' not in block_dict:
        return False
    if not isinstance(block_dict['T'], str):
        return False
    if not validate_target(block_dict['T']):
        return False

    if 'miner' in block_dict:
        if not isinstance(block_dict['miner'], str):
            return False
        if not block_dict['miner'].isascii():
            return False
        if len(block_dict['miner']) > 128:
            return False

    if 'note' in block_dict:
        if not isinstance(block_dict['note'], str):
            return False
        if not block_dict['note'].isascii():
            return False
        if len(block_dict['note']) > 128:
            return False

    if len(set(block_dict.keys()) - set(['type', 'txids', 'nonce', 'previd',
        'created', 'T', 'miner', 'note'])) != 0:
        return False

    return True

def validate_object(obj_dict):
    if not isinstance(obj_dict, dict):
        return False

    if 'type' not in obj_dict:
        return False
    if not isinstance(obj_dict['type'], str):
        return False

    obj_type = obj_dict['type']
    if obj_type == 'transaction':
        return validate_transaction(obj_dict)
    elif obj_type == 'block':
        return validate_block(obj_dict)

    return False

def expand_object(obj_str):
    return json.loads(obj_str)

def get_objid(obj_dict):
    h = hashlib.sha256()
    h.update(canonicalize(obj_dict))
    return h.hexdigest()

def verify_tx_signature(tx_dict, sig, pubkey):
    tx_local = copy.deepcopy(tx_dict)

    for i in tx_local['inputs']:
        i['sig'] = None

    pubkey_obj = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey))
    sig_bytes = bytes.fromhex(sig)

    try:
        pubkey_obj.verify(sig_bytes, canonicalize(tx_local))
    except InvalidSignature:
        return False

    return True

class TXVerifyException(Exception):
    pass

def verify_transaction(tx_dict, input_txs):
    # coinbase transaction
    if 'height' in tx_dict:
        return

    # regular transaction
    insum = 0
    in_dict = dict()
    for i in tx_dict['inputs']:
        ptxid = i['outpoint']['txid']
        ptxidx = i['outpoint']['index']

        if ptxid in in_dict:
            if ptxidx in in_dict[ptxid]:
                raise TXVerifyException("Multiple inputs have the same outpoint!")
            else:
                in_dict[ptxid].add(ptxidx)
        else:
            in_dict[ptxid] = {ptxidx}

        if ptxid not in input_txs:
            raise TXVerifyException("Previous TX '{}' missing!".format(ptxid))

        ptx_dict = input_txs[ptxid]

        # just to be sure
        if ptx_dict['type'] != 'transaction':
            raise TXVerifyException("Previous TX '{}' is not a transaction!".format(ptxid))

        if ptxidx >= len(ptx_dict['outputs']):
            raise TXVerifyException("Invalid output index in previous TX '{}'!".format(ptxid))

        output = ptx_dict['outputs'][ptxidx]
        if not verify_tx_signature(tx_dict, i['sig'], output['pubkey']):
            raise TXVerifyException("Invalid signature from previous TX '{}'!".format(ptxid))

        insum = insum + output['value']

    if insum < sum([o['value'] for o in tx_dict['outputs']]):
        raise TXVerifyException("Sum of inputs < sum of outputs!")

class BlockVerifyException(Exception):
    pass

def update_utxo_and_calculate_fee(tx, utxo):
    txid = get_objid(tx)

    invalue = 0
    for inp in tx['inputs']:
        in_txid = inp['outpoint']['txid']
        in_idx = "{}".format(inp['outpoint']['index'])

        if in_txid not in utxo:
            raise BlockVerifyException("Input for TX {} not in UTXO!".format(txid))
        if in_idx not in utxo[in_txid]:
            raise BlockVerifyException("Input for TX {} not in UTXO!".format(txid))

        invalue = invalue + utxo[in_txid][in_idx]

        del utxo[in_txid][in_idx]
        if len(utxo[in_txid]) == 0:
            del utxo[in_txid]

    outvalue = 0
    for out_idx in range(len(tx['outputs'])):
        out = tx['outputs'][out_idx]

        if txid not in utxo:
            utxo[txid] = dict()

        utxo[txid]["{}".format(out_idx)] = out['value']

        outvalue = outvalue + out['value']

    if outvalue > invalue:
        raise BlockVerifyException("Outputs for TX {} exceed inputs!".format(txid))

    return invalue - outvalue

def verify_block(block_dict):
    if block_dict['T'] != const.BLOCK_TARGET:
        raise BlockVerifyException("Invalid target!")

    if int(get_objid(block_dict), 16) >= int(const.BLOCK_TARGET, 16):
        raise BlockVerifyException("Block does not satisfy proof-of-work equation!")

    if block_dict['created'] > int(datetime.now().timestamp()):
        raise BlockVerifyException("Block created in the future!")

def verify_block_tail(block, prev_block, prev_utxo, prev_height, txs):
    if prev_block is None:
        if get_objid(block) != const.GENESIS_BLOCK_ID: 
            raise BlockVerifyException("Block does not contain link to previous "
                "or is fake genesis block!")
        prev_utxo = dict()
        prev_created_ts = 0
        prev_height = -1
    else:
        if prev_block['type'] != 'block':
            raise BlockVerifyException("Previous block is not a block!")
        if prev_utxo is None:
            raise BlockVerifyException("No UTXO for previous block found!")
        if prev_height is None:
            raise BlockVerifyException("No height for previous block found!")

        prev_created_ts = prev_block['created']

    # check block timestamp
    if prev_created_ts >= block['created']:
        raise BlockVerifyException("Block not created after previous block!")

    if any(tx['type'] != 'transaction' for tx in txs.values()):
        raise BlockVerifyException("Not all transactions are transactions!")

    height = prev_height + 1
    
    # no transactions, return old UTXO and height
    if len(block['txids']) == 0:
        return prev_utxo, height

    # recheck if we have all transactions
    for txid in block['txids']:
        if txid not in txs:
            raise BlockVerifyException("TX {} missing!".format(txid))

    first_txid = block['txids'][0]
    remaining_txids = block['txids']
    utxo = copy.deepcopy(prev_utxo)

    # do we have a coinbase TX?
    cbtx = None
    cbtxid = None
    if 'height' in txs[first_txid]:
        cbtx = txs[first_txid]
        cbtxid = first_txid
        remaining_txids = block['txids'][1:]

        # add coinbase TX output to UTXO
        utxo[cbtxid] = { '0': cbtx['outputs'][0]['value'] }

        # check coinbase (if included in block) height
        if cbtx['height'] != height:
            raise BlockVerifyException("Coinbase TX height invalid!")

    txfees = 0
    for txid in remaining_txids:
        # check for additional coinbase transactions
        if 'height' in txs[txid]:
            raise BlockVerifyException("Coinbase TX {} not at index 0!".format(txid))

        tx = txs[txid]

        # check if the coinbase is spent in the same block
        if any(inp['outpoint']['txid'] == cbtxid for inp in tx['inputs']):
            raise BlockVerifyException("Coinbase TX spent in same block!")

        # check and update UTXO
        fee = update_utxo_and_calculate_fee(tx, utxo)

        txfees = txfees + fee

    # check coinbase output value
    if cbtx is not None:
        if cbtx['outputs'][0]['value'] < const.BLOCK_REWARD:
            raise BlockVerifyException("Coinbase TX output value too small")
        if cbtx['outputs'][0]['value'] > const.BLOCK_REWARD + txfees:
            raise BlockVerifyException("Coinbase TX output value too big")

    return utxo, height
