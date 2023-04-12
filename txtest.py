from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import copy

import objects

SAMPLE_CBTX = {
        "height":0,
        "outputs":[
            {
                "pubkey":"8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9",
                "value":50000000000
            }
        ],
        "type":"transaction"
}

SAMPLE_TX = {
        "inputs":[
            {
                "outpoint":{
                    "index":0,
                    "txid":"1bb37b637d07100cd26fc063dfd4c39a7931cc88dae3417871219715a5e374af"
                },
                "sig":"1d0d7d774042607c69a87ac5f1cdf92bf474c25fafcc089fe667602bfefb0494726c519e92266957429ced875256e6915eb8cea2ea66366e739415efc47a6805"
            }
        ],
        "outputs":[
            {
                "pubkey":"8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9",
                "value":10
            }
        ],
        "type":"transaction"
}

CBTX_1OUT_SKEL = {
        "height":0,
        "outputs":[
            {
                "pubkey":None,
                "value":0
            }
        ],
        "type":"transaction"
}

TX_1IN_1OUT_SKEL = {
        "inputs":[
            {
                "outpoint":{
                    "index":0,
                    "txid":None
                },
                "sig":None
            }
        ],
        "outputs":[
            {
                "pubkey":None,
                "value":0
            }
        ],
        "type":"transaction"
}

TX_1IN_2OUT_SKEL = {
        "inputs":[
            {
                "outpoint":{
                    "index":0,
                    "txid":None
                },
                "sig":None
            }
        ],
        "outputs":[
            {
                "pubkey":None,
                "value":0
            },
            {
                "pubkey":None,
                "value":0
            }
        ],
        "type":"transaction"
}

TX_1IN_3OUT_SKEL = {
        "inputs":[
            {
                "outpoint":{
                    "index":0,
                    "txid":None
                },
                "sig":None
            }
        ],
        "outputs":[
            {
                "pubkey":None,
                "value":0
            },
            {
                "pubkey":None,
                "value":0
            },
            {
                "pubkey":None,
                "value":0
            }
        ],
        "type":"transaction"
}

TX_2IN_1OUT_SKEL = {
        "inputs":[
            {
                "outpoint":{
                    "index":0,
                    "txid":None
                },
                "sig":None
            },
            {
                "outpoint":{
                    "index":0,
                    "txid":None
                },
                "sig":None
            },
        ],
        "outputs":[
            {
                "pubkey":None,
                "value":0
            }
        ],
        "type":"transaction"
}

TX_3IN_1OUT_SKEL = {
        "inputs":[
            {
                "outpoint":{
                    "index":0,
                    "txid":None
                },
                "sig":None
            },
            {
                "outpoint":{
                    "index":0,
                    "txid":None
                },
                "sig":None
            },
            {
                "outpoint":{
                    "index":0,
                    "txid":None
                },
                "sig":None
            },
        ],
        "outputs":[
            {
                "pubkey":None,
                "value":0
            }
        ],
        "type":"transaction"
}

def verify_tx(tx, prev_txs):
    ptx = {}
    for p in prev_txs:
        ptx[objects.get_objid(p)] = p

    try:
        if not objects.validate_transaction(tx):
            raise objects.TXVerifyException("Syntax validation failed!")
        objects.verify_transaction(tx, ptx)
        print("Verified!")
    except objects.TXVerifyException as e:
        print("Verification failed: {}".format(str(e)))

def mk_cbtx_invalid_1():
    print(">>> Invalid CBTX: negative height")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()

    cbtx1 = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx1['height'] = -1
    cbtx1['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx1['outputs'][0]['value'] = 50

    print("=== CBTX {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))
    verify_tx(cbtx1, [])

    print()

def mk_cbtx_invalid_2():
    print(">>> Invalid CBTX: negative value")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()

    cbtx1 = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx1['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx1['outputs'][0]['value'] = -50

    print("=== CBTX {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))
    verify_tx(cbtx1, [])

    print()

def mk_cbtx_invalid_3():
    print(">>> Invalid CBTX: multiple outputs")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()

    cbtx1 = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx1['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx1['outputs'][0]['value'] = 50
    cbtx1['outputs'].append({})
    cbtx1['outputs'][1]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx1['outputs'][1]['value'] = 20

    print("=== CBTX {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))
    verify_tx(cbtx1, [])

    print()

def mk_cbtx_invalid_4():
    print(">>> Invalid CBTX: no outputs")

    cbtx1 = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx1['outputs'] = []

    print("=== CBTX {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))
    verify_tx(cbtx1, [])

    print()

def mk_2cbtx_1tx_sane_1():
    print(">>> Valid TX spending from two CBTXs")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()
    sk2 = Ed25519PrivateKey.generate()
    pk2 = sk2.public_key()

    cbtx1 = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx1['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx1['outputs'][0]['value'] = 50

    print("=== CBTX {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))
    verify_tx(cbtx1, [])

    cbtx2 = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx2['outputs'][0]['pubkey'] = pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx2['outputs'][0]['value'] = 50

    print("=== CBTX {} ===".format(objects.get_objid(cbtx2)))
    print(objects.canonicalize(cbtx2).decode('utf-8'))
    verify_tx(cbtx2, [])
   
    tx = copy.deepcopy(TX_2IN_1OUT_SKEL)
    tx['inputs'][0]['outpoint']['txid'] = objects.get_objid(cbtx1)
    tx['inputs'][1]['outpoint']['txid'] = objects.get_objid(cbtx2)
    tx['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx['outputs'][0]['value'] = 20
    sig1 = sk1.sign(objects.canonicalize(tx))
    sig2 = sk2.sign(objects.canonicalize(tx))
    tx['inputs'][0]['sig'] = sig1.hex()
    tx['inputs'][1]['sig'] = sig2.hex()

    print("=== TX {} ===".format(objects.get_objid(tx)))
    print(objects.canonicalize(tx).decode('utf-8'))
    verify_tx(tx, [cbtx1, cbtx2])

    print()

def mk_1cbtx_1tx_sane_1():
    print(">>> Valid TX spending from one CBTX")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()

    cbtx = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx['outputs'][0]['value'] = 50

    print("=== CBTX {} ===".format(objects.get_objid(cbtx)))
    print(objects.canonicalize(cbtx).decode('utf-8'))
    verify_tx(cbtx, [])

    tx = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx['inputs'][0]['outpoint']['txid'] = objects.get_objid(cbtx)
    tx['inputs'][0]['outpoint']['index'] = 0
    tx['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx['outputs'][0]['value'] = 50
    sig1 = sk1.sign(objects.canonicalize(tx))
    tx['inputs'][0]['sig'] = sig1.hex()

    print("=== TX {} ===".format(objects.get_objid(tx)))
    print(objects.canonicalize(tx).decode('utf-8'))
    verify_tx(tx, [cbtx])

    print()

def mk_1cbtx_1tx_invalid_1():
    print(">>> Invalid TX spending from one CBTX: outputs > inputs")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()

    cbtx = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx['outputs'][0]['value'] = 50

    print("=== CBTX {} ===".format(objects.get_objid(cbtx)))
    print(objects.canonicalize(cbtx).decode('utf-8'))
    verify_tx(cbtx, [])

    tx = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx['inputs'][0]['outpoint']['txid'] = objects.get_objid(cbtx)
    tx['inputs'][0]['outpoint']['index'] = 0
    tx['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx['outputs'][0]['value'] = 51
    sig1 = sk1.sign(objects.canonicalize(tx))
    tx['inputs'][0]['sig'] = sig1.hex()

    print("=== TX {} ===".format(objects.get_objid(tx)))
    print(objects.canonicalize(tx).decode('utf-8'))
    verify_tx(tx, [cbtx])

    print()

def mk_1cbtx_1tx_invalid_2():
    print(">>> Invalid TX spending from one CBTX: invalid index in outpoint")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()

    cbtx = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx['outputs'][0]['value'] = 50

    print("=== CBTX {} ===".format(objects.get_objid(cbtx)))
    print(objects.canonicalize(cbtx).decode('utf-8'))
    verify_tx(cbtx, [])

    tx = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx['inputs'][0]['outpoint']['txid'] = objects.get_objid(cbtx)
    tx['inputs'][0]['outpoint']['index'] = 1
    tx['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx['outputs'][0]['value'] = 50
    sig1 = sk1.sign(objects.canonicalize(tx))
    tx['inputs'][0]['sig'] = sig1.hex()

    print("=== TX {} ===".format(objects.get_objid(tx)))
    print(objects.canonicalize(tx).decode('utf-8'))
    verify_tx(tx, [cbtx])

    print()

def mk_1cbtx_1tx_invalid_3():
    print(">>> Invalid TX spending from one CBTX: no outputs")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()

    cbtx = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx['outputs'][0]['value'] = 50

    print("=== CBTX {} ===".format(objects.get_objid(cbtx)))
    print(objects.canonicalize(cbtx).decode('utf-8'))
    verify_tx(cbtx, [])

    tx = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx['inputs'][0]['outpoint']['txid'] = objects.get_objid(cbtx)
    tx['inputs'][0]['outpoint']['index'] = 0
    tx['outputs'] = []
    sig1 = sk1.sign(objects.canonicalize(tx))
    tx['inputs'][0]['sig'] = sig1.hex()

    print("=== TX {} ===".format(objects.get_objid(tx)))
    print(objects.canonicalize(tx).decode('utf-8'))
    verify_tx(tx, [cbtx])

    print()

def mk_1tx_invalid_1():
    print(">>> Invalid TX: no inputs")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()

    tx = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx['inputs'] = []
    tx['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx['outputs'][0]['value'] = 0

    print("=== TX {} ===".format(objects.get_objid(tx)))
    print(objects.canonicalize(tx).decode('utf-8'))
    verify_tx(tx, [])

    print()

def check_sample_txs():
    print(">>> Valid TX spending from one CBTX: example from task description")

    print("=== CBTX {} ===".format(objects.get_objid(SAMPLE_CBTX)))
    print(objects.canonicalize(SAMPLE_CBTX).decode('utf-8'))
    verify_tx(SAMPLE_CBTX, [])

    print("=== TX {} ===".format(objects.get_objid(SAMPLE_TX)))
    print(objects.canonicalize(SAMPLE_TX).decode('utf-8'))
    verify_tx(SAMPLE_TX, [SAMPLE_CBTX])

    print()

def mk_1cbtx_2tx_sane_1():
    print(">>> Valid TX sequence 1")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()
    sk2 = Ed25519PrivateKey.generate()
    pk2 = sk2.public_key()

    cbtx = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx['outputs'][0]['value'] = 50

    print("=== CBTX {} ===".format(objects.get_objid(cbtx)))
    print(objects.canonicalize(cbtx).decode('utf-8'))
    verify_tx(cbtx, [])

    tx = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx['inputs'][0]['outpoint']['txid'] = objects.get_objid(cbtx)
    tx['inputs'][0]['outpoint']['index'] = 0
    tx['outputs'][0]['pubkey'] = pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx['outputs'][0]['value'] = 50
    sig1 = sk1.sign(objects.canonicalize(tx))
    tx['inputs'][0]['sig'] = sig1.hex()

    print("=== TX {} ===".format(objects.get_objid(tx)))
    print(objects.canonicalize(tx).decode('utf-8'))
    verify_tx(tx, [cbtx])

    tx2 = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx2['inputs'][0]['outpoint']['txid'] = objects.get_objid(tx)
    tx2['inputs'][0]['outpoint']['index'] = 0
    tx2['outputs'][0]['pubkey'] = pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx2['outputs'][0]['value'] = 50
    sig2 = sk2.sign(objects.canonicalize(tx2))
    tx2['inputs'][0]['sig'] = sig2.hex()

    print("=== TX {} ===".format(objects.get_objid(tx2)))
    print(objects.canonicalize(tx2).decode('utf-8'))
    verify_tx(tx2, [tx])

    print()

def mk_2cbtx_2tx_double_spend_1():
    print(">>> Valid TX sequence with double-spending 1")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()
    sk2 = Ed25519PrivateKey.generate()
    pk2 = sk2.public_key()

    print("{}: {}".format(
        pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        sk1.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    ))
    print("{}: {}".format(
        pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        sk2.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    ))

    cbtx1 = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx1['height'] = 1
    cbtx1['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx1['outputs'][0]['value'] = 50000000000000

    print("=== CBTX {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))
    verify_tx(cbtx1, [])

    cbtx2 = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx2['height'] = 2
    cbtx2['outputs'][0]['pubkey'] = pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx2['outputs'][0]['value'] = 50000000000000

    print("=== CBTX {} ===".format(objects.get_objid(cbtx2)))
    print(objects.canonicalize(cbtx2).decode('utf-8'))
    verify_tx(cbtx2, [])

    tx1 = copy.deepcopy(TX_2IN_1OUT_SKEL)
    tx1['inputs'][0]['outpoint']['txid'] = objects.get_objid(cbtx1)
    tx1['inputs'][1]['outpoint']['txid'] = objects.get_objid(cbtx2)
    tx1['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx1['outputs'][0]['value'] = 20
    sig1 = sk1.sign(objects.canonicalize(tx1))
    sig2 = sk2.sign(objects.canonicalize(tx1))
    tx1['inputs'][0]['sig'] = sig1.hex()
    tx1['inputs'][1]['sig'] = sig2.hex()

    print("=== TX {} ===".format(objects.get_objid(tx1)))
    print(objects.canonicalize(tx1).decode('utf-8'))
    verify_tx(tx1, [cbtx1, cbtx2])

    tx2 = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx2['inputs'][0]['outpoint']['txid'] = objects.get_objid(cbtx1)
    tx2['outputs'][0]['pubkey'] = pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx2['outputs'][0]['value'] = 50
    sig1 = sk1.sign(objects.canonicalize(tx2))
    tx2['inputs'][0]['sig'] = sig1.hex()

    print("=== TX {} ===".format(objects.get_objid(tx2)))
    print(objects.canonicalize(tx2).decode('utf-8'))
    verify_tx(tx2, [cbtx1])

    print()

def mk_1cbtx_2tx_internal_double_spend_1():
    print(">>> Valid TX sequence with internal double-spending 1")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()
    sk2 = Ed25519PrivateKey.generate()
    pk2 = sk2.public_key()
    sk3 = Ed25519PrivateKey.generate()
    pk3 = sk3.public_key()

    print("{}: {}".format(
        pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        sk1.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    ))
    print("{}: {}".format(
        pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        sk2.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    ))
    print("{}: {}".format(
        pk3.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        sk3.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    ))

    cbtx1 = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx1['height'] = 1
    cbtx1['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx1['outputs'][0]['value'] = 50000000000000

    print("=== CBTX {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))
    verify_tx(cbtx1, [])

    tx1 = copy.deepcopy(TX_1IN_3OUT_SKEL)
    tx1['inputs'][0]['outpoint']['txid'] = objects.get_objid(cbtx1)
    tx1['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx1['outputs'][0]['value'] = 20
    tx1['outputs'][1]['pubkey'] = pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx1['outputs'][1]['value'] = 20
    tx1['outputs'][2]['pubkey'] = pk3.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx1['outputs'][2]['value'] = 20
    sig1 = sk1.sign(objects.canonicalize(tx1))
    tx1['inputs'][0]['sig'] = sig1.hex()

    print("=== TX {} ===".format(objects.get_objid(tx1)))
    print(objects.canonicalize(tx1).decode('utf-8'))
    verify_tx(tx1, [cbtx1])

    tx2 = copy.deepcopy(TX_3IN_1OUT_SKEL)
    tx2['inputs'][0]['outpoint']['txid'] = objects.get_objid(tx1)
    tx2['inputs'][0]['outpoint']['index'] = 0
    tx2['inputs'][1]['outpoint']['txid'] = objects.get_objid(tx1)
    tx2['inputs'][1]['outpoint']['index'] = 1
    tx2['inputs'][2]['outpoint']['txid'] = objects.get_objid(tx1)
    tx2['inputs'][2]['outpoint']['index'] = 0
    tx2['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx2['outputs'][0]['value'] = 60
    sig1 = sk1.sign(objects.canonicalize(tx2))
    sig2 = sk2.sign(objects.canonicalize(tx2))
    sig3 = sk1.sign(objects.canonicalize(tx2))
    tx2['inputs'][0]['sig'] = sig1.hex()
    tx2['inputs'][1]['sig'] = sig2.hex()
    tx2['inputs'][2]['sig'] = sig3.hex()

    print("=== TX {} ===".format(objects.get_objid(tx2)))
    print(objects.canonicalize(tx2).decode('utf-8'))
    verify_tx(tx2, [tx1])

    print()

def mk_tree_multiple_double_spend_1():
    print(">>> Valid TX tree with multiple double-spending TXs 1")

    sk1 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key()
    sk2 = Ed25519PrivateKey.generate()
    pk2 = sk2.public_key()
    sk3 = Ed25519PrivateKey.generate()
    pk3 = sk3.public_key()

    print("{}: {}".format(
        pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        sk1.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    ))
    print("{}: {}".format(
        pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        sk2.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    ))
    print("{}: {}".format(
        pk3.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
        sk3.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    ))

    cbtx1 = copy.deepcopy(CBTX_1OUT_SKEL)
    cbtx1['height'] = 1
    cbtx1['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    cbtx1['outputs'][0]['value'] = 50000000000000

    print("=== CBTX {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))
    verify_tx(cbtx1, [])

    tx1 = copy.deepcopy(TX_1IN_3OUT_SKEL)
    tx1['inputs'][0]['outpoint']['txid'] = objects.get_objid(cbtx1)
    tx1['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx1['outputs'][0]['value'] = 20
    tx1['outputs'][1]['pubkey'] = pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx1['outputs'][1]['value'] = 20
    tx1['outputs'][2]['pubkey'] = pk3.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx1['outputs'][2]['value'] = 20
    sig1 = sk1.sign(objects.canonicalize(tx1))
    tx1['inputs'][0]['sig'] = sig1.hex()

    print("=== TX {} ===".format(objects.get_objid(tx1)))
    print(objects.canonicalize(tx1).decode('utf-8'))
    verify_tx(tx1, [cbtx1])

    tx2 = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx2['inputs'][0]['outpoint']['txid'] = objects.get_objid(tx1)
    tx2['inputs'][0]['outpoint']['index'] = 0
    tx2['outputs'][0]['pubkey'] = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx2['outputs'][0]['value'] = 20
    sig1 = sk1.sign(objects.canonicalize(tx2))
    tx2['inputs'][0]['sig'] = sig1.hex()

    print("=== TX both {} ===".format(objects.get_objid(tx2)))
    print(objects.canonicalize(tx2).decode('utf-8'))
    verify_tx(tx2, [tx1])

    tx3 = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx3['inputs'][0]['outpoint']['txid'] = objects.get_objid(tx1)
    tx3['inputs'][0]['outpoint']['index'] = 1
    tx3['outputs'][0]['pubkey'] = pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx3['outputs'][0]['value'] = 20
    sig1 = sk2.sign(objects.canonicalize(tx3))
    tx3['inputs'][0]['sig'] = sig1.hex()

    print("=== TX left {} ===".format(objects.get_objid(tx3)))
    print(objects.canonicalize(tx3).decode('utf-8'))
    verify_tx(tx3, [tx1])

    tx4 = copy.deepcopy(TX_2IN_1OUT_SKEL)
    tx4['inputs'][0]['outpoint']['txid'] = objects.get_objid(tx3)
    tx4['inputs'][0]['outpoint']['index'] = 0
    tx4['inputs'][1]['outpoint']['txid'] = objects.get_objid(tx2)
    tx4['inputs'][1]['outpoint']['index'] = 0
    tx4['outputs'][0]['pubkey'] = pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx4['outputs'][0]['value'] = 40
    sig1 = sk2.sign(objects.canonicalize(tx4))
    sig2 = sk1.sign(objects.canonicalize(tx4))
    tx4['inputs'][0]['sig'] = sig1.hex()
    tx4['inputs'][1]['sig'] = sig2.hex()

    print("=== TX left {} ===".format(objects.get_objid(tx4)))
    print(objects.canonicalize(tx4).decode('utf-8'))
    verify_tx(tx4, [tx2, tx3])

    tx5 = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx5['inputs'][0]['outpoint']['txid'] = objects.get_objid(tx1)
    tx5['inputs'][0]['outpoint']['index'] = 1
    tx5['outputs'][0]['pubkey'] = pk3.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx5['outputs'][0]['value'] = 20
    sig1 = sk2.sign(objects.canonicalize(tx5))
    tx5['inputs'][0]['sig'] = sig1.hex()

    print("=== TX right {} ===".format(objects.get_objid(tx5)))
    print(objects.canonicalize(tx5).decode('utf-8'))
    verify_tx(tx5, [tx1])

    tx6 = copy.deepcopy(TX_2IN_1OUT_SKEL)
    tx6['inputs'][0]['outpoint']['txid'] = objects.get_objid(tx5)
    tx6['inputs'][0]['outpoint']['index'] = 0
    tx6['inputs'][1]['outpoint']['txid'] = objects.get_objid(tx2)
    tx6['inputs'][1]['outpoint']['index'] = 0
    tx6['outputs'][0]['pubkey'] = pk3.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx6['outputs'][0]['value'] = 40
    sig1 = sk3.sign(objects.canonicalize(tx6))
    sig2 = sk1.sign(objects.canonicalize(tx6))
    tx6['inputs'][0]['sig'] = sig1.hex()
    tx6['inputs'][1]['sig'] = sig2.hex()

    print("=== TX right {} ===".format(objects.get_objid(tx6)))
    print(objects.canonicalize(tx6).decode('utf-8'))
    verify_tx(tx6, [tx2, tx5])

    tx7 = copy.deepcopy(TX_1IN_1OUT_SKEL)
    tx7['inputs'][0]['outpoint']['txid'] = objects.get_objid(tx1)
    tx7['inputs'][0]['outpoint']['index'] = 2
    tx7['outputs'][0]['pubkey'] = pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tx7['outputs'][0]['value'] = 20
    sig1 = sk3.sign(objects.canonicalize(tx7))
    tx7['inputs'][0]['sig'] = sig1.hex()

    print("=== TX left {} ===".format(objects.get_objid(tx7)))
    print(objects.canonicalize(tx7).decode('utf-8'))
    verify_tx(tx7, [tx1])

    print()

def main():
    check_sample_txs()
    mk_cbtx_invalid_1()
    mk_cbtx_invalid_2()
    mk_cbtx_invalid_3()
    mk_cbtx_invalid_4()
    mk_2cbtx_1tx_sane_1()
    mk_1cbtx_1tx_sane_1()
    mk_1cbtx_1tx_invalid_1()
    mk_1cbtx_1tx_invalid_2()
    mk_1cbtx_1tx_invalid_3()
    mk_1tx_invalid_1()
    mk_1cbtx_2tx_sane_1()
    mk_2cbtx_2tx_double_spend_1()
    mk_1cbtx_2tx_internal_double_spend_1()
    mk_tree_multiple_double_spend_1()

if __name__ == "__main__":
    main()
