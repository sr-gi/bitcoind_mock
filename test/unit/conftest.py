import pytest
import random
from time import sleep
from threading import Thread

import bitcoind_mock.conf as conf
from bitcoind_mock.bitcoind import BitcoindMock
from bitcoind_mock.auth_proxy import AuthServiceProxy


def get_random_value_hex(nbytes):
    pseudo_random_value = random.getrandbits(8 * nbytes)
    prv_hex = "{:x}".format(pseudo_random_value)
    return prv_hex.zfill(2 * nbytes)


def bitcoin_cli():
    return AuthServiceProxy(
        "http://%s:%s@%s:%d" % (conf.BTC_RPC_USER, conf.BTC_RPC_PASSWD, conf.BTC_RPC_HOST, conf.BTC_RPC_PORT)
    )


@pytest.fixture(scope="module")
def run_bitcoind():
    bitcoind_thread = Thread(target=BitcoindMock().run, kwargs={"mode": "event"})
    bitcoind_thread.daemon = True
    bitcoind_thread.start()

    # It takes a little bit of time to start the API (otherwise the requests are sent too early and they fail)
    sleep(0.1)


@pytest.fixture(scope="module")
def genesis_block_hash(run_bitcoind):
    return bitcoin_cli().getblockhash(0)
