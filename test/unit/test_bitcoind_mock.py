import re
import requests
from threading import Thread

from test.unit.conftest import get_random_value_hex, bitcoin_cli

import bitcoind_mock.conf as conf
from bitcoind_mock.transaction import TX
from bitcoind_mock.bitcoind import BitcoindMock, set_event
from bitcoind_mock.auth_proxy import JSONRPCException

MIXED_VALUES = values = [-1, 500, "", "111", [], 1.1, None, "", "a" * 31, "b" * 33, get_random_value_hex(32)]


def check_hash_format(txid):
    return isinstance(txid, str) and re.search(r"^[0-9A-Fa-f]{64}$", txid) is not None


def test_get_rpc_param():
    # get_rpc_param should return the first param of a list
    params = {"params": list(range(100))}

    while len(params["params"]) > 0:
        param = BitcoindMock().get_rpc_param(params)
        first_param = params["params"].pop(0)
        assert param == first_param


def test_get_new_block_data(run_bitcoind):
    # Not much to test here, the function should return a tuple of three elements of the proper size and format
    block_hash, coinbase_tx, coinbase_tx_hash = BitcoindMock.get_new_block_data()

    assert check_hash_format(block_hash) and check_hash_format(coinbase_tx_hash)
    assert isinstance(coinbase_tx, str) and isinstance(TX.deserialize(coinbase_tx), TX)


def test_generate():
    best_block_hash = bitcoin_cli().getbestblockhash()
    best_block = bitcoin_cli().getblock(best_block_hash)

    requests.post(url="http://{}:{}/generate".format(conf.BTC_RPC_HOST, conf.BTC_RPC_PORT), timeout=5)

    new_best_block_hash = bitcoin_cli().getbestblockhash()
    new_best_block = bitcoin_cli().getblock(new_best_block_hash)

    assert best_block_hash != new_best_block_hash
    assert new_best_block.get("height") == best_block.get("height") + 1


def test_create_fork():
    best_block_hash = bitcoin_cli().getbestblockhash()

    requests.post(url="http://{}:{}/generate".format(conf.BTC_RPC_HOST, conf.BTC_RPC_PORT), timeout=5)

    new_best_block_hash = bitcoin_cli().getbestblockhash()

    # Create a fork (new block at same height as old best)
    requests.post(
        url="http://{}:{}/fork".format(conf.BTC_RPC_HOST, conf.BTC_RPC_PORT),
        json={"parent": best_block_hash},
        timeout=5,
    )
    # Mine an additional block to make the best tip change
    requests.post(url="http://{}:{}/generate".format(conf.BTC_RPC_HOST, conf.BTC_RPC_PORT), timeout=5)

    # Check that the old best block is now in a fork
    orphan_block = bitcoin_cli().getblock(new_best_block_hash)
    assert orphan_block.get("confirmations") == -1
    assert orphan_block.get("previousblockhash") == best_block_hash

    new_best_block_hash = bitcoin_cli().getbestblockhash()
    forked_block = bitcoin_cli().getblock(new_best_block_hash)

    # Check that the new best links to the original best
    assert forked_block.get("confirmations") == bitcoin_cli().getblock(best_block_hash).get("confirmations") - 2
    assert bitcoin_cli().getblock(forked_block.get("previousblockhash")).get("previousblockhash") == best_block_hash


def test_set_event():
    bitcoind_mock = BitcoindMock()
    t = Thread(target=set_event, args=[bitcoind_mock.mine_new_block, 0.1])
    t.daemon = True
    t.start()

    # The event will be triggered after 0.1 second, so we can just hook to it and see how it goes off
    for i in range(10):
        bitcoind_mock.mine_new_block.clear()
        bitcoind_mock.mine_new_block.wait()
    assert True


# process_request is tested through the different rpc commands.
# FIXME: Better assert for the exceptions would be nice (check the returned errno is the expected one)
def test_getblock(genesis_block_hash):
    # getblock should return a list of transactions and the height
    block = bitcoin_cli().getblock(genesis_block_hash)
    assert isinstance(block.get("tx"), list)
    assert len(block.get("tx")) != 0
    assert isinstance(block.get("height"), int)

    # It should fail for wrong data formats and random ids
    for v in MIXED_VALUES:
        try:
            bitcoin_cli().getblock(v)
            assert False
        except JSONRPCException as e:
            assert True

    best_block = bitcoin_cli().getblock(bitcoin_cli().getbestblockhash())
    requests.post(url="http://{}:{}/generate".format(conf.BTC_RPC_HOST, conf.BTC_RPC_PORT), timeout=5)

    # Check that the confirmation counting works
    old_best = bitcoin_cli().getblock(best_block.get("hash"))
    best_block = bitcoin_cli().getblock(bitcoin_cli().getbestblockhash())

    assert best_block.get("confirmations") == old_best.get("confirmations") - 1


def test_decoderawtransaction(genesis_block_hash):
    # decoderawtransaction should only return if the given transaction is properly formatted (can be deserialized using
    # (TX.deserialize(raw_tx).
    block = bitcoin_cli().getblock(genesis_block_hash)
    coinbase_txid = block.get("tx")[0]

    coinbase_tx = bitcoin_cli().getrawtransaction(coinbase_txid).get("hex")
    tx = bitcoin_cli().decoderawtransaction(coinbase_tx)

    assert isinstance(tx, dict)
    assert isinstance(tx.get("txid"), str)
    assert check_hash_format(tx.get("txid"))

    # Therefore it should also work for a random transaction hex in our simulation
    random_tx = TX.create_dummy_transaction()
    tx = bitcoin_cli().decoderawtransaction(random_tx)
    assert isinstance(tx, dict)
    assert isinstance(tx.get("txid"), str)
    assert check_hash_format(tx.get("txid"))

    # But it should fail for not proper formatted one
    for v in MIXED_VALUES:
        try:
            bitcoin_cli().decoderawtransaction(v)
            assert False
        except JSONRPCException as e:
            assert True


def test_sendrawtransaction(genesis_block_hash):
    # sendrawtransaction should only allow txs that the simulator has not mined yet
    bitcoin_cli().sendrawtransaction(TX.create_dummy_transaction())

    # Any tx with invalid format or that matches with an already mined transaction should fail
    try:
        # Trying to resend the coinbase tx of the genesis block
        genesis_tx = bitcoin_cli().getblock(genesis_block_hash).get("tx")[0]
        bitcoin_cli().sendrawtransaction(genesis_tx)
        assert False

    except JSONRPCException as e:
        assert True

    for v in MIXED_VALUES:
        # Sending random values
        try:
            bitcoin_cli().sendrawtransaction(v)
            assert False
        except JSONRPCException as e:
            assert True

    # Trying with a valid tx
    try:
        tx = TX.create_dummy_transaction()
        bitcoin_cli().sendrawtransaction(tx)
        assert True

    except JSONRPCException as e:
        assert False


def test_getrawtransaction(genesis_block_hash):
    # getrawtransaction should work for existing transactions, and fail for non-existing ones
    genesis_tx = bitcoin_cli().getblock(genesis_block_hash).get("tx")[0]
    tx = bitcoin_cli().getrawtransaction(genesis_tx)

    assert isinstance(tx, dict)
    assert isinstance(tx.get("confirmations"), int)

    for v in MIXED_VALUES:
        try:
            bitcoin_cli().getrawtransaction(v)
            assert False
        except JSONRPCException as e:
            assert True


def test_getblockcount():
    # getblockcount should always return a positive integer
    bc = bitcoin_cli().getblockcount()
    assert isinstance(bc, int)
    assert bc >= 0


def test_getblockhash(genesis_block_hash):
    # First block
    assert bitcoin_cli().getblockhash(0) == genesis_block_hash

    # Check that the values are within range and of the proper format (all should fail)
    for v in MIXED_VALUES:
        try:
            bitcoin_cli().getblockhash(v)
            assert False
        except JSONRPCException as e:
            assert True


def test_getbestblockhash():
    # Get block hash should return the tip of the best chain
    best_block_hash = bitcoin_cli().getbestblockhash()

    # If we generate a new block, the tip should that block
    requests.post(url="http://{}:{}/generate".format(conf.BTC_RPC_HOST, conf.BTC_RPC_PORT), timeout=5)
    new_best_block_hash = bitcoin_cli().getbestblockhash()

    assert bitcoin_cli().getblock(new_best_block_hash).get("previousblockhash") == best_block_hash

    # If we fork and generate a few blocks (surpassing the current tip) the best block hash should change
    requests.post(
        url="http://{}:{}/fork".format(conf.BTC_RPC_HOST, conf.BTC_RPC_PORT),
        json={"parent": best_block_hash},
        timeout=5,
    )

    # The tip should still be the same (we have a block at the same height but the previous one was seen first)
    assert bitcoin_cli().getbestblockhash() == new_best_block_hash

    requests.post(url="http://{}:{}/generate".format(conf.BTC_RPC_HOST, conf.BTC_RPC_PORT), timeout=5)

    # The tip should have changed now, and the old chain should be a fork
    assert bitcoin_cli().getbestblockhash() != new_best_block_hash
    assert bitcoin_cli().getblock(new_best_block_hash).get("confirmations") == -1


def test_help():
    # Help should always return 0
    assert bitcoin_cli().help() == 0


# This two functions are indirectly tested by the rest
def test_simulate_mining():
    pass


def test_run():
    pass
