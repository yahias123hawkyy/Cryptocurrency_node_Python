# This script depens on the DB being preloaded with transactions and blocks
# from the testcase "Block tree for mempool testing 1.1" from blocktest.py
import objects
import mempool

BOTH_TXID = "71cf54aa33437af755a535392264953f7a422d688cea41c979bba2652df54e60"
LEFT_TXID_1 = "d01ddb20ed4053065e481ffc2ddd6b525eaae87f82d14f9e53090741a2d5d717"
LEFT_TXID_2 = "6d349b209b1d29f07b181741dc824fd65979fa8d0f6e62ba9c6a60797102b661"
LEFT_TXID_3 = "c7034431f14c3fd85c72b6255d367f5803bbd91b1fc66a8aa9545ce948d0c5af"
RIGHT_TXID_1 = "9d7844e4adeb99213f69c98dda6aeae2ce8a2e911379eb0ca96ff478658d0bdb"
RIGHT_TXID_2 = "07c9900bdb1b199c6c198900f23694294fb9497fb3335608e7186ffe5f561ce3"

BASE_TIP = "00000002820b886211848314aae50b5669fb17a0b576f12c6f307ae728f2723f"
LEFT_TIP = "00000000718a8413bf487ba8ab9b70c39299c88d2a6ed7fb8a0a8d1deee58a7e"
RIGHT_TIP = "0000000032576f3434300007cb0ea6e653a25b4358a46905453cf0193dc24986"

def main():
    print(">>> Reorg left to right")
    utxo, newmp = mempool.rebase_mempool(LEFT_TIP, RIGHT_TIP, [])
    print("UTXO: {}".format(utxo))
    print("NEWMP: {}".format(newmp))
    print()

    print(">>> Extend base to left with left MP")
    utxo, newmp = mempool.rebase_mempool(BASE_TIP, LEFT_TIP, [BOTH_TXID, LEFT_TXID_1, LEFT_TXID_2, LEFT_TXID_3])
    print("UTXO: {}".format(utxo))
    print("NEWMP: {}".format(newmp))
    print()

    print(">>> Extend base to right with right MP")
    utxo, newmp = mempool.rebase_mempool(BASE_TIP, RIGHT_TIP, [BOTH_TXID, RIGHT_TXID_1, RIGHT_TXID_2])
    print("UTXO: {}".format(utxo))
    print("NEWMP: {}".format(newmp))
    print()

    print(">>> Extend base to left with right MP")
    utxo, newmp = mempool.rebase_mempool(BASE_TIP, LEFT_TIP, [BOTH_TXID, RIGHT_TXID_1, RIGHT_TXID_2])
    print("UTXO: {}".format(utxo))
    print("NEWMP: {}".format(newmp))
    print()

    print(">>> Extend base to right with left MP")
    utxo, newmp = mempool.rebase_mempool(BASE_TIP, RIGHT_TIP, [BOTH_TXID, LEFT_TXID_1, LEFT_TXID_2, LEFT_TXID_3])
    print("UTXO: {}".format(utxo))
    print("NEWMP: {}".format(newmp))
    print()

if __name__ == "__main__":
    main()
