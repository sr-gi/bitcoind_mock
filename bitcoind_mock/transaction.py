from riemann import tx
from riemann import utils as rutils

from bitcoind_mock import utils


def create_dummy_transaction(prev_tx_id=None, prev_out_index=None):
    if prev_tx_id is None or len(prev_tx_id) != 64:
        prev_tx_id = utils.get_random_value_hex(32)

    idx = prev_out_index if prev_out_index is not None else 0
    prev_out_index_bytes = rutils.i2le_padded(idx, 4).hex()

    dummy_hex = f"0100000001{prev_tx_id}{prev_out_index_bytes}4847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0100f2052a01000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00000000"

    return tx.Tx.from_hex(dummy_hex)
