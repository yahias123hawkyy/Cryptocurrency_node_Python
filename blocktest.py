import objects

import copy
import hashlib

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

GENESIS_BLOCK_ALT = {
        "created":1624219079,
        "miner":"dionyziz",
        "nonce":"00000000000000000000000000000000000000000000000000000000187e8b0f",
        "note":"The Economist 2021-06-20: Crypto-miners are probably to blame for the graphics-chip shortage",
        "previd":None,
        "txids":[],
        "type":"block",
        "T":"00000002af000000000000000000000000000000000000000000000000000000",
}

BLOCK_SKEL = {
        "created":None,
        "miner":"Snekel testminer",
        "nonce":None,
        "note":"This is a test block",
        "previd":None,
        "txids":[],
        "type":"block",
        "T":"00000002af000000000000000000000000000000000000000000000000000000",
}

test_double_spend_1_sk1 = 'e61508c18a17d79e745f87258fdc446e4159ff91b78e677503af7ad1c45a6223'
test_double_spend_1_sk2 = '526bc55b2d1ea64758543e1f3614fa0af9ec927671d6d047b5e4849556b274b8'
test_double_spend_1_cbtx1 = '{"height":1,"outputs":[{"pubkey":"f66c7d51551d344b74e071d3b988d2bc09c3ffa82857302620d14f2469cfbf60","value":50000000000000}],"type":"transaction"}'
test_double_spend_1_cbtx2 = '{"height":2,"outputs":[{"pubkey":"c7c2c13afd02be7986dee0f4630df01abdbc950ea379055f1a423a6090f1b2b3","value":50000000000000}],"type":"transaction"}'
test_double_spend_1_tx1 = '{"inputs":[{"outpoint":{"index":0,"txid":"2a9458a2e75ed8bd0341b3cb2ab21015bbc13f21ea06229340a7b2b75720c4df"},"sig":"334939cac007a71e72484ffa5f34fabe3e3aff31297003a7d3d24795ed33d04a72f8b14316bce3e6467b2f6e66d481f8142ccd9933279fdcb3aef7ace145f10b"},{"outpoint":{"index":0,"txid":"73231cc901774ddb4196ee7e9e6b857b208eea04aee26ced038ac465e1e706d2"},"sig":"032c6c0a1074b7a965e58fa5071aa9e518bf5c4db9e2880ca5bb5c55dcea47cfd6e0a9859526a16d2bb0b46da0ca4c6f90be8ddf16b149be66016d7f272e6708"}],"outputs":[{"pubkey":"f66c7d51551d344b74e071d3b988d2bc09c3ffa82857302620d14f2469cfbf60","value":20}],"type":"transaction"}'
test_double_spend_1_tx2 = '{"inputs":[{"outpoint":{"index":0,"txid":"2a9458a2e75ed8bd0341b3cb2ab21015bbc13f21ea06229340a7b2b75720c4df"},"sig":"49cc4f9a1fb9d600a7debc99150e7909274c8c74edd7ca183626dfe49eb4aa21c6ff0e4c5f0dc2a328ad6b8ba10bf7169d5f42993a94bf67e13afa943b749c0b"}],"outputs":[{"pubkey":"c7c2c13afd02be7986dee0f4630df01abdbc950ea379055f1a423a6090f1b2b3","value":50}],"type":"transaction"}'
test_coinbase_output_1_cbtx_max = '{"height":2,"outputs":[{"pubkey":"c7c2c13afd02be7986dee0f4630df01abdbc950ea379055f1a423a6090f1b2b3","value":99999999999950}],"type":"transaction"}'
test_coinbase_output_1_cbtx_over = '{"height":2,"outputs":[{"pubkey":"c7c2c13afd02be7986dee0f4630df01abdbc950ea379055f1a423a6090f1b2b3","value":99999999999951}],"type":"transaction"}'
test_coinbase_output_1_cbtx_under = '{"height":2,"outputs":[{"pubkey":"c7c2c13afd02be7986dee0f4630df01abdbc950ea379055f1a423a6090f1b2b3","value":49999999999999}],"type":"transaction"}'

test_mempool_1_sk1 = '1468c133e2ee2d10656bd4724856d20da8993cb4a31480782df8e49125c95bbc'
test_mempool_1_sk2 = '192427d56c88202692642c3213c2777b26dbb441258812a74fcdd63e70427795'
test_mempool_1_sk3 = '1e8ae3ac246385373d9c1343a5ccc9c751a150f65880ce1d7ab08e765c5978b6'
test_mempool_1_base_cbtx1 = '{"height":1,"outputs":[{"pubkey":"d06c56f71b18c36f795c629cf4987e23b126fa0244cc25c971b318215665fdd7","value":50000000000000}],"type":"transaction"}'
test_mempool_1_base_tx1 = '{"inputs":[{"outpoint":{"index":0,"txid":"e24e57fc271f743a33e67a061e19769a8251fd9f849d9b7e77bb7d1470f8a79c"},"sig":"642783ab5b4520f00cd9a0de816c05ad8715e5f2562f9ca564b12fc1e2265a89a748b64d891f7ee54e018a01f6fbad920d753d07d1472b6bea87d42412319c08"}],"outputs":[{"pubkey":"d06c56f71b18c36f795c629cf4987e23b126fa0244cc25c971b318215665fdd7","value":20},{"pubkey":"651c0cc3312b984c964d04d51c12bd8a211f3fa586b9fa59ffd6944a3c7d2451","value":20},{"pubkey":"4c9a153dec5e0315dcc5964a789446b9760856bfc45eaa966ec7cd40974b8490","value":20}],"type":"transaction"}'
test_mempool_1_both_tx1 = '{"inputs":[{"outpoint":{"index":0,"txid":"71cf54aa33437af755a535392264953f7a422d688cea41c979bba2652df54e60"},"sig":"9d311aed691e8d3987992fe6aca75c08f3be26aa5b133ef430d9d027460a3962bcd5703832bef46af0c6558ad36e9c4a6539d188338456d404d8c3b18269b409"}],"outputs":[{"pubkey":"d06c56f71b18c36f795c629cf4987e23b126fa0244cc25c971b318215665fdd7","value":20}],"type":"transaction"}'
test_mempool_1_left_tx1 = '{"inputs":[{"outpoint":{"index":1,"txid":"71cf54aa33437af755a535392264953f7a422d688cea41c979bba2652df54e60"},"sig":"ff13f0a72250efa66ad14459f6511120476f5dd21171380ccb70207b1c916c49eea8600ea770786614f34d7e12629d1c0c99c348a633b84e3a316b76fa16cc03"}],"outputs":[{"pubkey":"651c0cc3312b984c964d04d51c12bd8a211f3fa586b9fa59ffd6944a3c7d2451","value":20}],"type":"transaction"}'
test_mempool_1_left_tx2 = '{"inputs":[{"outpoint":{"index":0,"txid":"d01ddb20ed4053065e481ffc2ddd6b525eaae87f82d14f9e53090741a2d5d717"},"sig":"0968d6cdc3fb4f65c0e5a162e01cc5f6fa29446086585016aceefbf2d229fff2925703aedca18ff1fea4db651b72458efbfeef3f404451cffd8c26988c319603"},{"outpoint":{"index":0,"txid":"00eef7b3d265288f4a51a09837f0763ed1093d96a1fe2c6e01979eb35e4ff63b"},"sig":"24d2e74ec7bc7b8b43146618d47de773bf90be2a4aa045fbba5631a768005a21f25dc73e8e9d6e4a37161b7ba9e00e05b4e245353ff7b092a637313494fc2700"}],"outputs":[{"pubkey":"651c0cc3312b984c964d04d51c12bd8a211f3fa586b9fa59ffd6944a3c7d2451","value":40}],"type":"transaction"}'
test_mempool_1_left_tx3 = '{"inputs":[{"outpoint":{"index":2,"txid":"71cf54aa33437af755a535392264953f7a422d688cea41c979bba2652df54e60"},"sig":"b65cf22242c85d259976c24593c1e7635e1cfbd3b1ee33f2ef311badb064c9389529b0e7b9100e30fbebbfa8fffa5e20335794399af074796638a7bd59f3580f"}],"outputs":[{"pubkey":"651c0cc3312b984c964d04d51c12bd8a211f3fa586b9fa59ffd6944a3c7d2451","value":20}],"type":"transaction"}'
test_mempool_1_right_tx1 = '{"inputs":[{"outpoint":{"index":1,"txid":"71cf54aa33437af755a535392264953f7a422d688cea41c979bba2652df54e60"},"sig":"0c700e9337f55bf722bf2b8e18e3615a34ad2e8f3005519314d4abad2c1cf6dfed4a08d9d2833ed6f8d45f87a89d9fd7f5bc1f6321b5c59ffc53e4df04069209"}],"outputs":[{"pubkey":"4c9a153dec5e0315dcc5964a789446b9760856bfc45eaa966ec7cd40974b8490","value":20}],"type":"transaction"}'
test_mempool_1_right_tx2 = '{"inputs":[{"outpoint":{"index":0,"txid":"9d7844e4adeb99213f69c98dda6aeae2ce8a2e911379eb0ca96ff478658d0bdb"},"sig":"59a0aeaed33755c21941626228219127c5029744e0630bc8e3824c4e02b81ce9c5cc6ac5e44c1b4d3465d09297d9a79d1f47dce0f0794e9426781a0c75f36b0b"},{"outpoint":{"index":0,"txid":"00eef7b3d265288f4a51a09837f0763ed1093d96a1fe2c6e01979eb35e4ff63b"},"sig":"63112999ed78334653fbda50ff03bd4344685c907ee5180a740a077bbe157da883dca75abbeb184db3d41af8d4e6105694419107de03dc306342038b7432f107"}],"outputs":[{"pubkey":"4c9a153dec5e0315dcc5964a789446b9760856bfc45eaa966ec7cd40974b8490","value":40}],"type":"transaction"}'

def get_hash_prefix(block_pre_bytes):
    h = hashlib.sha256()
    h.update(block_pre_bytes)
    return h

def get_hash_nonce(h, nonce_bytes):
    h2 = h.copy()
    h2.update(nonce_bytes)
    return h2

def get_hash_postfix(h, block_post_bytes):
    h.update(block_post_bytes)
    return h.digest()

def mine_block(block):
    nonce = 0
    target = int(block['T'], 16)

    block['nonce'] = "^"
    block_parts = objects.canonicalize(block).decode('utf-8').split('^')
    block_pre_bytes = block_parts[0].encode('utf-8')
    block_post_bytes = block_parts[1].encode('utf-8')

    h_prefix = get_hash_prefix(block_pre_bytes)
    h = get_hash_nonce(h_prefix, format(nonce, '064x').encode('utf-8'))
    blockid = get_hash_postfix(h, block_post_bytes)

    while int.from_bytes(blockid, 'big', signed = False) >= target:
        subtarget = nonce + (1024*1024)
        while nonce < subtarget and int.from_bytes(blockid, 'big', signed = False) >= target:
            nonce = nonce + 1
            h = get_hash_nonce(h_prefix, format(nonce, '064x').encode('utf-8'))
            blockid = get_hash_postfix(h, block_post_bytes)

        print("Current nonce: {}".format(format(nonce, '064x')))

    print(">>> Valid nonce found!")
    blockid_str = format(int.from_bytes(blockid, 'big', signed = False), '064x')
    nonce_str = format(nonce, '064x')
    block['nonce'] = nonce_str
    print("=== Nonce {} ===".format(nonce_str))
    print("=== Block ID {} ===".format(blockid_str))

def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    try:
        if not objects.validate_block(block):
            raise objects.BlockVerifyException("Syntax validation failed!")
        objects.verify_block(block)
        new_utxo, new_height = objects.verify_block_tail(block, prev_block, prev_utxo,
                prev_height, txs)
        print("Verified!")
        return new_utxo
    except objects.BlockVerifyException as e:
        print("Verification failed: {}".format(str(e)))
        return prev_utxo

def check_genesis():
    print(">>> Valid genesis block")

    print("=== Genesis block {} ===".format(objects.get_objid(GENESIS_BLOCK)))
    print(objects.canonicalize(GENESIS_BLOCK).decode('utf-8'))
    genesis_utxo = verify_block(GENESIS_BLOCK, None, None, None, dict())
    print("=== UTXO ===")
    print(genesis_utxo)

    print()

def check_genesis_alt():
    print(">>> Valid alternative genesis block")

    print("=== Genesis block {} ===".format(objects.get_objid(GENESIS_BLOCK_ALT)))
    print(objects.canonicalize(GENESIS_BLOCK_ALT).decode('utf-8'))
    genesis_alt_utxo = verify_block(GENESIS_BLOCK_ALT, None, None, None, dict())
    print("=== UTXO ===")
    print(genesis_alt_utxo)

    print()

def mk_block_seq_double_spend_1_1():
    print(">>> Block sequence with double spending 1.1")

    cbtx1 = objects.expand_object(test_double_spend_1_cbtx1)
    print("=== CBTX 1 {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))

    block1 = copy.deepcopy(BLOCK_SKEL)
    block1['created'] = GENESIS_BLOCK['created'] + 1000
    block1['previd'] = objects.get_objid(GENESIS_BLOCK)
    block1['txids'] = [objects.get_objid(cbtx1)]
    block1['note'] = "First block after genesis with CBTX"
    block1['nonce'] = "000000000000000000000000000000000000000000000000000000009d8b60ea"
    print("=== {} {} ===".format(block1['note'], objects.get_objid(block1)))
    print(objects.canonicalize(block1).decode('utf-8'))
    block1_utxo = verify_block(block1, GENESIS_BLOCK, dict(), 0, {
        objects.get_objid(cbtx1): cbtx1
    })
    print("=== UTXO ===")
    print(block1_utxo)

    cbtx2 = objects.expand_object(test_double_spend_1_cbtx2)
    print("=== CBTX 2 {} ===".format(objects.get_objid(cbtx2)))
    print(objects.canonicalize(cbtx2).decode('utf-8'))

    tx2 = objects.expand_object(test_double_spend_1_tx2)
    print("=== TX 2 {} ===".format(objects.get_objid(tx2)))
    print(objects.canonicalize(tx2).decode('utf-8'))

    block2 = copy.deepcopy(BLOCK_SKEL)
    block2['created'] = block1['created'] + 1000
    block2['previd'] = objects.get_objid(block1)
    block2['txids'] = [objects.get_objid(cbtx2), objects.get_objid(tx2)]
    block2['note'] = "Second block after genesis with CBTX and TX"
    block2['nonce'] = "00000000000000000000000000000000000000000000000000000000182b95ea"
    print("=== {} {} ===".format(block2['note'], objects.get_objid(block2)))
    print(objects.canonicalize(block2).decode('utf-8'))
    block2_utxo = verify_block(block2, block1, block1_utxo, 1, {
        objects.get_objid(cbtx2): cbtx2,
        objects.get_objid(tx2): tx2,
    })
    print("=== UTXO ===")
    print(block2_utxo)

    tx1 = objects.expand_object(test_double_spend_1_tx1)
    print("=== TX 1 {} ===".format(objects.get_objid(tx1)))
    print(objects.canonicalize(tx1).decode('utf-8'))

    block3 = copy.deepcopy(BLOCK_SKEL)
    block3['created'] = block2['created'] + 1000
    block3['previd'] = objects.get_objid(block2)
    block3['txids'] = [objects.get_objid(tx1)]
    block3['note'] = "Third block after genesis with double-spending TX"
    block3['nonce'] = "0000000000000000000000000000000000000000000000000000000010fea5cc"
    print("=== {} {} ===".format(block3['note'], objects.get_objid(block3)))
    print(objects.canonicalize(block3).decode('utf-8'))
    block3_utxo = verify_block(block3, block2, block2_utxo, 2, {
        objects.get_objid(tx1): tx1,
    })
    print("=== UTXO ===")
    print(block3_utxo)

    print()

def mk_block_seq_double_spend_1_2():
    print(">>> Block sequence with double spending 1.2")

    cbtx1 = objects.expand_object(test_double_spend_1_cbtx1)
    print("=== CBTX 1 {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))

    block1 = copy.deepcopy(BLOCK_SKEL)
    block1['created'] = GENESIS_BLOCK['created'] + 1000
    block1['previd'] = objects.get_objid(GENESIS_BLOCK)
    block1['txids'] = [objects.get_objid(cbtx1)]
    block1['note'] = "First block after genesis with CBTX"
    block1['nonce'] = "000000000000000000000000000000000000000000000000000000009d8b60ea"
    print("=== {} {} ===".format(block1['note'], objects.get_objid(block1)))
    print(objects.canonicalize(block1).decode('utf-8'))
    block1_utxo = verify_block(block1, GENESIS_BLOCK, dict(), 0, {
        objects.get_objid(cbtx1): cbtx1
    })
    print("=== UTXO ===")
    print(block1_utxo)

    cbtx2 = objects.expand_object(test_double_spend_1_cbtx2)
    print("=== CBTX 2 {} ===".format(objects.get_objid(cbtx2)))
    print(objects.canonicalize(cbtx2).decode('utf-8'))

    block2 = copy.deepcopy(BLOCK_SKEL)
    block2['created'] = block1['created'] + 1000
    block2['previd'] = objects.get_objid(block1)
    block2['txids'] = [objects.get_objid(cbtx2)]
    block2['note'] = "Second block after genesis with CBTX"
    block2['nonce'] = "000000000000000000000000000000000000000000000000000000004d82fc68"
    print("=== {} {} ===".format(block2['note'], objects.get_objid(block2)))
    print(objects.canonicalize(block2).decode('utf-8'))
    block2_utxo = verify_block(block2, block1, block1_utxo, 1, {
        objects.get_objid(cbtx2): cbtx2,
    })
    print("=== UTXO ===")
    print(block2_utxo)

    tx1 = objects.expand_object(test_double_spend_1_tx1)
    print("=== TX 1 {} ===".format(objects.get_objid(tx1)))
    print(objects.canonicalize(tx1).decode('utf-8'))

    tx2 = objects.expand_object(test_double_spend_1_tx2)
    print("=== TX 2 {} ===".format(objects.get_objid(tx2)))
    print(objects.canonicalize(tx2).decode('utf-8'))

    block3 = copy.deepcopy(BLOCK_SKEL)
    block3['created'] = block2['created'] + 1000
    block3['previd'] = objects.get_objid(block2)
    block3['txids'] = [objects.get_objid(tx1), objects.get_objid(tx2)]
    block3['note'] = "Third block after genesis with double-spending TX"
    block3['nonce'] = "00000000000000000000000000000000000000000000000000000000062d431b"
    print("=== {} {} ===".format(block3['note'], objects.get_objid(block3)))
    print(objects.canonicalize(block3).decode('utf-8'))
    block3_utxo = verify_block(block3, block2, block2_utxo, 2, {
        objects.get_objid(tx1): tx1,
        objects.get_objid(tx2): tx2,
    })
    print("=== UTXO ===")
    print(block3_utxo)

    print()

def mk_block_seq_spend_cbtx_in_same_block_1_1():
    print(">>> Block sequence spending a CBTX in the same block 1.1")

    cbtx1 = objects.expand_object(test_double_spend_1_cbtx1)
    print("=== CBTX 1 {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))

    tx2 = objects.expand_object(test_double_spend_1_tx2)
    print("=== TX 2 {} ===".format(objects.get_objid(tx2)))
    print(objects.canonicalize(tx2).decode('utf-8'))

    block1 = copy.deepcopy(BLOCK_SKEL)
    block1['created'] = GENESIS_BLOCK['created'] + 1000
    block1['previd'] = objects.get_objid(GENESIS_BLOCK)
    block1['txids'] = [objects.get_objid(cbtx1), objects.get_objid(tx2)]
    block1['note'] = "First block after genesis with CBTX and TX spending it"
    block1['nonce'] = "000000000000000000000000000000000000000000000000000000001beecbf3"
    print("=== {} {} ===".format(block1['note'], objects.get_objid(block1)))
    print(objects.canonicalize(block1).decode('utf-8'))
    block1_utxo = verify_block(block1, GENESIS_BLOCK, dict(), 0, {
        objects.get_objid(cbtx1): cbtx1,
        objects.get_objid(tx2): tx2
    })
    print("=== UTXO ===")
    print(block1_utxo)

    print()

def mk_block_seq_coinbase_max_1_1():
    print(">>> Block sequence with maximum coinbase output 1.1")

    cbtx1 = objects.expand_object(test_double_spend_1_cbtx1)
    print("=== CBTX 1 {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))

    block1 = copy.deepcopy(BLOCK_SKEL)
    block1['created'] = GENESIS_BLOCK['created'] + 1000
    block1['previd'] = objects.get_objid(GENESIS_BLOCK)
    block1['txids'] = [objects.get_objid(cbtx1)]
    block1['note'] = "First block after genesis with CBTX"
    block1['nonce'] = "000000000000000000000000000000000000000000000000000000009d8b60ea"
    print("=== {} {} ===".format(block1['note'], objects.get_objid(block1)))
    print(objects.canonicalize(block1).decode('utf-8'))
    block1_utxo = verify_block(block1, GENESIS_BLOCK, dict(), 0, {
        objects.get_objid(cbtx1): cbtx1
    })
    print("=== UTXO ===")
    print(block1_utxo)

    cbtx2 = objects.expand_object(test_coinbase_output_1_cbtx_max)
    print("=== CBTX 2 {} ===".format(objects.get_objid(cbtx2)))
    print(objects.canonicalize(cbtx2).decode('utf-8'))

    tx2 = objects.expand_object(test_double_spend_1_tx2)
    print("=== TX 2 {} ===".format(objects.get_objid(tx2)))
    print(objects.canonicalize(tx2).decode('utf-8'))

    block2 = copy.deepcopy(BLOCK_SKEL)
    block2['created'] = block1['created'] + 1000
    block2['previd'] = objects.get_objid(block1)
    block2['txids'] = [objects.get_objid(cbtx2), objects.get_objid(tx2)]
    block2['note'] = "Second block after genesis with maximum CBTX and TX"
    block2['nonce'] = "0000000000000000000000000000000000000000000000000000000183d8f97d"
    print("=== {} {} ===".format(block2['note'], objects.get_objid(block2)))
    print(objects.canonicalize(block2).decode('utf-8'))
    block2_utxo = verify_block(block2, block1, block1_utxo, 1, {
        objects.get_objid(cbtx2): cbtx2,
        objects.get_objid(tx2): tx2,
    })
    print("=== UTXO ===")
    print(block2_utxo)

    print()

def mk_block_seq_coinbase_over_1_1():
    print(">>> Block sequence with too high a coinbase output 1.1")

    cbtx1 = objects.expand_object(test_double_spend_1_cbtx1)
    print("=== CBTX 1 {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))

    block1 = copy.deepcopy(BLOCK_SKEL)
    block1['created'] = GENESIS_BLOCK['created'] + 1000
    block1['previd'] = objects.get_objid(GENESIS_BLOCK)
    block1['txids'] = [objects.get_objid(cbtx1)]
    block1['note'] = "First block after genesis with CBTX"
    block1['nonce'] = "000000000000000000000000000000000000000000000000000000009d8b60ea"
    print("=== {} {} ===".format(block1['note'], objects.get_objid(block1)))
    print(objects.canonicalize(block1).decode('utf-8'))
    block1_utxo = verify_block(block1, GENESIS_BLOCK, dict(), 0, {
        objects.get_objid(cbtx1): cbtx1
    })
    print("=== UTXO ===")
    print(block1_utxo)

    cbtx2 = objects.expand_object(test_coinbase_output_1_cbtx_over)
    print("=== CBTX 2 {} ===".format(objects.get_objid(cbtx2)))
    print(objects.canonicalize(cbtx2).decode('utf-8'))

    tx2 = objects.expand_object(test_double_spend_1_tx2)
    print("=== TX 2 {} ===".format(objects.get_objid(tx2)))
    print(objects.canonicalize(tx2).decode('utf-8'))

    block2 = copy.deepcopy(BLOCK_SKEL)
    block2['created'] = block1['created'] + 1000
    block2['previd'] = objects.get_objid(block1)
    block2['txids'] = [objects.get_objid(cbtx2), objects.get_objid(tx2)]
    block2['note'] = "Second block after genesis with CBTX with too high an output and TX"
    block2['nonce'] = "0000000000000000000000000000000000000000000000000000000014fce4ac"
    print("=== {} {} ===".format(block2['note'], objects.get_objid(block2)))
    print(objects.canonicalize(block2).decode('utf-8'))
    block2_utxo = verify_block(block2, block1, block1_utxo, 1, {
        objects.get_objid(cbtx2): cbtx2,
        objects.get_objid(tx2): tx2,
    })
    print("=== UTXO ===")
    print(block2_utxo)

    print()

def mk_block_seq_coinbase_under_1_1():
    print(">>> Block sequence with too low a coinbase output 1.1")

    cbtx1 = objects.expand_object(test_double_spend_1_cbtx1)
    print("=== CBTX 1 {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))

    block1 = copy.deepcopy(BLOCK_SKEL)
    block1['created'] = GENESIS_BLOCK['created'] + 1000
    block1['previd'] = objects.get_objid(GENESIS_BLOCK)
    block1['txids'] = [objects.get_objid(cbtx1)]
    block1['note'] = "First block after genesis with CBTX"
    block1['nonce'] = "000000000000000000000000000000000000000000000000000000009d8b60ea"
    print("=== {} {} ===".format(block1['note'], objects.get_objid(block1)))
    print(objects.canonicalize(block1).decode('utf-8'))
    block1_utxo = verify_block(block1, GENESIS_BLOCK, dict(), 0, {
        objects.get_objid(cbtx1): cbtx1
    })
    print("=== UTXO ===")
    print(block1_utxo)

    cbtx2 = objects.expand_object(test_coinbase_output_1_cbtx_under)
    print("=== CBTX 2 {} ===".format(objects.get_objid(cbtx2)))
    print(objects.canonicalize(cbtx2).decode('utf-8'))

    tx2 = objects.expand_object(test_double_spend_1_tx2)
    print("=== TX 2 {} ===".format(objects.get_objid(tx2)))
    print(objects.canonicalize(tx2).decode('utf-8'))

    block2 = copy.deepcopy(BLOCK_SKEL)
    block2['created'] = block1['created'] + 1000
    block2['previd'] = objects.get_objid(block1)
    block2['txids'] = [objects.get_objid(cbtx2), objects.get_objid(tx2)]
    block2['note'] = "Second block after genesis with CBTX with too low an output and TX"
    block2['nonce'] = "000000000000000000000000000000000000000000000000000000000940f6d6"
    print("=== {} {} ===".format(block2['note'], objects.get_objid(block2)))
    print(objects.canonicalize(block2).decode('utf-8'))
    block2_utxo = verify_block(block2, block1, block1_utxo, 1, {
        objects.get_objid(cbtx2): cbtx2,
        objects.get_objid(tx2): tx2,
    })
    print("=== UTXO ===")
    print(block2_utxo)

    print()

def mk_block_seq_nonexistent_tx_1_1():
    print(">>> Block sequence with a nonexistent transaction 1.1")

    block1 = copy.deepcopy(BLOCK_SKEL)
    block1['created'] = GENESIS_BLOCK['created'] + 1000
    block1['previd'] = objects.get_objid(GENESIS_BLOCK)
    block1['txids'] = ["9ad6b1e11f08fcc11b9e811ad5bc518fd3121c56822c4e87d8523eb2d35fdda6"]
    block1['note'] = "First block after genesis with nonexistent TX"
    block1['nonce'] = "0000000000000000000000000000000000000000000000000000000014844510"
    print("=== {} {} ===".format(block1['note'], objects.get_objid(block1)))
    print(objects.canonicalize(block1).decode('utf-8'))
    block1_utxo = verify_block(block1, GENESIS_BLOCK, dict(), 0, dict())
    print("=== UTXO ===")
    print(block1_utxo)

    print()

def mk_block_seq_invalid_cbtx_height_1_1():
    print(">>> Block sequence with a coinbase transaction at invalid height 1.1")

    cbtx2 = objects.expand_object(test_double_spend_1_cbtx2)
    print("=== CBTX 2 {} ===".format(objects.get_objid(cbtx2)))
    print(objects.canonicalize(cbtx2).decode('utf-8'))

    block1 = copy.deepcopy(BLOCK_SKEL)
    block1['created'] = GENESIS_BLOCK['created'] + 1000
    block1['previd'] = objects.get_objid(GENESIS_BLOCK)
    block1['txids'] = [objects.get_objid(cbtx2)]
    block1['note'] = "First block after genesis with CBTX at invalid height"
    block1['nonce'] = "000000000000000000000000000000000000000000000000000000003cef2f58"
    print("=== {} {} ===".format(block1['note'], objects.get_objid(block1)))
    print(objects.canonicalize(block1).decode('utf-8'))
    block1_utxo = verify_block(block1, GENESIS_BLOCK, dict(), 0, {
        objects.get_objid(cbtx2): cbtx2,
    })
    print("=== UTXO ===")
    print(block1_utxo)

    print()

def mk_block_tree_mempool_1_1():
    print(">>> Block tree for mempool testing 1.1")

    cbtx1 = objects.expand_object(test_mempool_1_base_cbtx1)
    print("=== Base CBTX 1 {} ===".format(objects.get_objid(cbtx1)))
    print(objects.canonicalize(cbtx1).decode('utf-8'))

    block1 = copy.deepcopy(BLOCK_SKEL)
    block1['created'] = GENESIS_BLOCK['created'] + 1000
    block1['previd'] = objects.get_objid(GENESIS_BLOCK)
    block1['txids'] = [objects.get_objid(cbtx1)]
    block1['note'] = "First base block after genesis with CBTX"
    block1['nonce'] = "000000000000000000000000000000000000000000000000000000007c101512"
    print("=== {} {} ===".format(block1['note'], objects.get_objid(block1)))
    print(objects.canonicalize(block1).decode('utf-8'))
    block1_utxo = verify_block(block1, GENESIS_BLOCK, dict(), 0, {
        objects.get_objid(cbtx1): cbtx1
    })
    print("=== UTXO ===")
    print(block1_utxo)

    tx1 = objects.expand_object(test_mempool_1_base_tx1)
    print("=== Base TX 1 {} ===".format(objects.get_objid(tx1)))
    print(objects.canonicalize(tx1).decode('utf-8'))

    block2 = copy.deepcopy(BLOCK_SKEL)
    block2['created'] = block1['created'] + 1000
    block2['previd'] = objects.get_objid(block1)
    block2['txids'] = [objects.get_objid(tx1)]
    block2['note'] = "Second base block after genesis with TX"
    block2['nonce'] = "000000000000000000000000000000000000000000000000000000000f4ee346"
    print("=== {} {} ===".format(block2['note'], objects.get_objid(block2)))
    print(objects.canonicalize(block2).decode('utf-8'))
    block2_utxo = verify_block(block2, block1, block1_utxo, 1, {
        objects.get_objid(tx1): tx1,
    })
    print("=== UTXO ===")
    print(block2_utxo)

    tx2 = objects.expand_object(test_mempool_1_both_tx1)
    print("=== Both TX 1 {} ===".format(objects.get_objid(tx2)))
    print(objects.canonicalize(tx2).decode('utf-8'))

    tx3 = objects.expand_object(test_mempool_1_left_tx1)
    print("=== Left TX 1 {} ===".format(objects.get_objid(tx3)))
    print(objects.canonicalize(tx3).decode('utf-8'))

    tx4 = objects.expand_object(test_mempool_1_left_tx2)
    print("=== Left TX 2 {} ===".format(objects.get_objid(tx4)))
    print(objects.canonicalize(tx4).decode('utf-8'))

    tx5 = objects.expand_object(test_mempool_1_left_tx3)
    print("=== Left TX 3 {} ===".format(objects.get_objid(tx5)))
    print(objects.canonicalize(tx5).decode('utf-8'))

    block3 = copy.deepcopy(BLOCK_SKEL)
    block3['created'] = block2['created'] + 1000
    block3['previd'] = objects.get_objid(block2)
    block3['txids'] = [objects.get_objid(tx2), objects.get_objid(tx3), objects.get_objid(tx4), objects.get_objid(tx5)]
    block3['note'] = "First left block after base with TXs"
    block3['nonce'] = "000000000000000000000000000000000000000000000000000000003543a6a3"
    print("=== {} {} ===".format(block3['note'], objects.get_objid(block3)))
    print(objects.canonicalize(block3).decode('utf-8'))
    block3_utxo = verify_block(block3, block2, block2_utxo, 2, {
        objects.get_objid(tx2): tx2,
        objects.get_objid(tx3): tx3,
        objects.get_objid(tx4): tx4,
        objects.get_objid(tx5): tx5,
    })
    print("=== UTXO ===")
    print(block3_utxo)

    tx6 = objects.expand_object(test_mempool_1_both_tx1)
    print("=== Both TX 1 {} ===".format(objects.get_objid(tx6)))
    print(objects.canonicalize(tx6).decode('utf-8'))

    tx7 = objects.expand_object(test_mempool_1_right_tx1)
    print("=== Right TX 1 {} ===".format(objects.get_objid(tx7)))
    print(objects.canonicalize(tx7).decode('utf-8'))

    tx8 = objects.expand_object(test_mempool_1_right_tx2)
    print("=== Right TX 2 {} ===".format(objects.get_objid(tx8)))
    print(objects.canonicalize(tx8).decode('utf-8'))

    block4 = copy.deepcopy(BLOCK_SKEL)
    block4['created'] = block2['created'] + 1000
    block4['previd'] = objects.get_objid(block2)
    block4['txids'] = [objects.get_objid(tx6), objects.get_objid(tx7), objects.get_objid(tx8)]
    block4['note'] = "First right block after base with TXs"
    block4['nonce'] = "00000000000000000000000000000000000000000000000000000000a2a34cf1"
    print("=== {} {} ===".format(block4['note'], objects.get_objid(block4)))
    print(objects.canonicalize(block4).decode('utf-8'))
    block4_utxo = verify_block(block4, block2, block2_utxo, 2, {
        objects.get_objid(tx6): tx6,
        objects.get_objid(tx7): tx7,
        objects.get_objid(tx8): tx8,
    })
    print("=== UTXO ===")
    print(block4_utxo)

    block5 = copy.deepcopy(BLOCK_SKEL)
    block5['created'] = block4['created'] + 1000
    block5['previd'] = objects.get_objid(block4)
    block5['txids'] = []
    block5['note'] = "Second right block after base without TXs"
    block5['nonce'] = "0000000000000000000000000000000000000000000000000000000012493fb8"
    print("=== {} {} ===".format(block5['note'], objects.get_objid(block5)))
    print(objects.canonicalize(block5).decode('utf-8'))
    block5_utxo = verify_block(block5, block4, block4_utxo, 3, {
    })
    print("=== UTXO ===")
    print(block5_utxo)

    print()

def main():
    check_genesis()
    check_genesis_alt()

    mk_block_seq_double_spend_1_1()
    mk_block_seq_double_spend_1_2()
    mk_block_seq_spend_cbtx_in_same_block_1_1()
    mk_block_seq_coinbase_max_1_1()
    mk_block_seq_coinbase_over_1_1()
    mk_block_seq_coinbase_under_1_1()
    mk_block_seq_nonexistent_tx_1_1()
    mk_block_seq_invalid_cbtx_height_1_1()
    mk_block_tree_mempool_1_1()

if __name__ == "__main__":
    main()
