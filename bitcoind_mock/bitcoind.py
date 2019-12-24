import os
import time
import json
import logging
import binascii
import networkx as nx
from copy import deepcopy
from networkx import NetworkXNoPath
from itertools import islice
from threading import Thread, Event
from flask import Flask, request, Response, abort

from bitcoind_mock.rpc_errors import *
import bitcoind_mock.conf as conf
from bitcoind_mock.utils import sha256d
from bitcoind_mock.transaction import TX
from bitcoind_mock.zmq_publisher import ZMQPublisher

app = Flask(__name__)
GENESIS_PARENT = "0000000000000000000000000000000000000000000000000000000000000000"


def set_event(event, wait_time):
    """
    Sets the mining event once every ``wait_time`` seconds so a new block is generated at fixed intervals.

    Args:
        event(:obj:`Event`): the event to be set.
        wait_time(:obj:`int`): time between blocks.
    """

    while True:
        time.sleep(wait_time)
        event.set()


class BitcoindMock:
    """
    Tiny mock of bitcoind. It creates a blockchain mock and a JSON-RCP interface. Let's you perform some of the bitcoind
    RPC commands (listed in process_request).

    Also let's you mine blocks by time or by demand, and create forks by demand.

    Attributes:
        blockchain(:obj:`DiGraph`): a directed graph representing the blockchain.
        blocks(:obj:`dict`): a dictionary keeping track of all blocks. Contains:
            ``{tx, height, previousblockhash, chainwork}``
        mempool(:obj:`dict`): a dictionary keeping track of the transactions pending to be mined.
        mempool(:obj:`dict`): a dictionary with all the mined transactions and a reference to the block where they were
            mined.
        mine_new_block(:obj:`Event`): an event flag to trigger a new block (if the mock is set to mine based on events).
        best_tip(:obj:`str`): a reference to the chain best tip.
        genesis(:obj:`str`): a reference to the chain genesis block.
        last_mined_block(:obj:`str`): a reference to the last mined block. The mock will mine on top of it.
    """

    def __init__(self):
        self.blockchain = nx.DiGraph()
        self.blocks = dict()
        self.mempool = dict()
        self.transactions = dict()
        self.mine_new_block = Event()

        # Create the genesis block
        block_hash, coinbase_tx, coinbase_tx_hash = self.get_new_block_data()
        self.transactions[coinbase_tx_hash] = {"tx": coinbase_tx, "block_hash": block_hash}

        self.blocks[block_hash] = {
            "tx": [coinbase_tx_hash],
            "height": 0,
            "previousblockhash": GENESIS_PARENT,
            "chainwork": 0,
        }
        self.blockchain.add_node(block_hash, short_id=block_hash[:8])
        self.best_tip = block_hash
        self.last_mined_block = block_hash
        self.genesis = block_hash

        # Set the event so it can start mining right off the bat
        self.mine_new_block.set()

    @staticmethod
    def get_rpc_param(request_data):
        """
        Gets the first parameter from a RPC call.

        Args:
            request_data(:obj:`list`): list of parameters from the rpc call.

        Returns:
              :obj:`str` or :obj:`None`: The first parameter of the call, or ``None`` if there are no parameters.
        """
        params = request_data.get("params")

        if isinstance(params, list) and len(params) > 0:
            return params[0]
        else:
            return None

    @staticmethod
    def get_new_block_data():
        """
        Creates the data to be used for a mined block.

       Returns:
            :obj:`tuple`: A three item tuple (block_hash, coinbase_tx, coinbase_tx_hash)
        """
        block_hash = os.urandom(32).hex()
        coinbase_tx = TX.create_dummy_transaction()
        coinbase_tx_hash = sha256d(coinbase_tx)

        return block_hash, coinbase_tx, coinbase_tx_hash

    def generate(self):
        """
        Endpoint use to trigger the mining of a new block. It can be accessed at ``/`` using ``POST``.

        Returns:
            :obj:`Response`: An HTTP 200-OK response signaling the acceptance of the request.
        """
        self.mine_new_block.set()

        return Response(status=200, mimetype="application/json")

    def create_fork(self):
        """
        Endpoint used to trigger a chain fork. It can be accessed at ``/fork`` using ``POST``.

        Requires a JSON encoded data with the key ``parent`` and the hash of an already mined block. The blockchain will
        be forked from the ``parent``.

        Returns:
            :obj:`Response`: An HTTP 200-OK response signaling the acceptance of the request if the parent was a valid
            block. An HTTP 200-OK with an error if the parent was invalid.
        """

        request_data = request.get_json()
        response = {"result": 0, "error": None}

        parent = request_data.get("parent")

        # FIXME: We only accept forks one by one for now

        if parent not in self.blocks:
            response["error"] = {"code": -1, "message": "Wrong parent block to fork from"}

        else:
            print("Forking chain from {}".format(parent))
            self.last_mined_block = parent
            self.generate()

        return Response(json.dumps(response), status=200, mimetype="application/json")

    def process_request(self):
        """
        Simulates the bitcoin-rpc server run by bitcoind. The available commands are limited to the ones we'll need to
        test out functionality. The model we will be using is pretty simplified to reduce the complexity of mocking
        bitcoind:

        decoderawtransaction:   querying for the decoding of a raw transaction will return a dictionary with a single
                                field: "txid".

        sendrawtransaction:     sending a rawtransaction will notify our mining simulator to include such transaction in
                                a subsequent block (add it to mempool).

        getrawtransaction:      requesting a rawtransaction from a txid will return a dictionary containing a single
                                field: "confirmations", since rawtransactions are only queried to check whether a
                                transaction has made it to a block or not.

        getblockcount:          the block count represents the length of the longest chain.

        getblock:               querying for a block will return a dictionary with three fields: "tx" representing a
                                list of transactions, "height" representing the block height and "hash" representing the
                                block hash.

        getblockhash:           returns the hash of a block given its height.

        getbestblockhash:       returns the hash of the block in the tip of the chain.

        help:                   help is only used as a sample command to test if bitcoind is running when bootstrapping.
                                It will return a 200/OK with no data.
        """

        request_data = request.get_json()
        method = request_data.get("method")

        response = {"id": 0, "result": 0, "error": None}
        no_param_err = {"code": RPC_MISC_ERROR, "message": "JSON value is not a {} as expected"}

        if method == "decoderawtransaction":
            rawtx = self.get_rpc_param(request_data)

            if isinstance(rawtx, str) and len(rawtx) % 2 is 0:
                txid = sha256d(rawtx)

                if TX.deserialize(rawtx) is not None:
                    response["result"] = {"txid": txid}

                else:
                    response["error"] = {"code": RPC_DESERIALIZATION_ERROR, "message": "TX decode failed"}

            else:
                response["error"] = no_param_err
                response["error"]["message"] = response["error"]["message"].format("string")

        elif method == "sendrawtransaction":
            # TODO: A way of rejecting transactions should be added to test edge cases.
            rawtx = self.get_rpc_param(request_data)

            if isinstance(rawtx, str) and len(rawtx) % 2 is 0:
                txid = sha256d(rawtx)

                if TX.deserialize(rawtx) is not None:
                    if txid not in self.transactions:
                        self.mempool[txid] = rawtx
                        response["result"] = {"txid": txid}

                    else:
                        response["error"] = {
                            "code": RPC_VERIFY_ALREADY_IN_CHAIN,
                            "message": "Transaction already in block chain",
                        }

                else:
                    response["error"] = {"code": RPC_DESERIALIZATION_ERROR, "message": "TX decode failed"}

            else:
                response["error"] = no_param_err
                response["error"]["message"] = response["error"]["message"].format("string")

        elif method == "getrawtransaction":
            txid = self.get_rpc_param(request_data)

            if isinstance(txid, str):
                if txid in self.transactions:
                    block_hash = self.transactions[txid]["block_hash"]
                    if self.in_best_chain(block_hash):
                        block = self.blocks.get(block_hash)
                        rawtx = self.transactions[txid].get("tx")
                        response["result"] = {
                            "hex": rawtx,
                            "confirmations": 1 + self.blocks.get(self.best_tip).get("height") - block.get("height"),
                        }
                    else:
                        response["error"] = {
                            "code": RPC_INVALID_ADDRESS_OR_KEY,
                            "message": "No such mempool or blockchain transaction. Use gettransaction for wallet "
                            "transactions.",
                        }

                elif txid in self.mempool:
                    response["result"] = {"confirmations": None}

                else:
                    response["error"] = {
                        "code": RPC_INVALID_ADDRESS_OR_KEY,
                        "message": "No such mempool or blockchain transaction. Use gettransaction for "
                        "wallet transactions.",
                    }

            else:
                response["error"] = no_param_err
                response["error"]["message"] = response["error"]["message"].format("string")

        elif method == "getblockcount":
            response["result"] = self.blocks[self.best_tip].get("height") + 1

        elif method == "getblock":
            block_hash = self.get_rpc_param(request_data)

            if isinstance(block_hash, str):
                block = deepcopy(self.blocks.get(block_hash))

                if block is not None:
                    if self.in_best_chain(block_hash):
                        block["confirmations"] = 1 + self.blocks.get(self.best_tip).get("height") - block.get("height")
                    else:
                        block["confirmations"] = -1

                    # chainwork is returned as a 32-byte hex by bitcoind
                    block["chainwork"] = "{:064x}".format(block["chainwork"])
                    block["hash"] = block_hash
                    response["result"] = block

                else:
                    response["error"] = {"code": RPC_INVALID_ADDRESS_OR_KEY, "message": "Block not found"}

            else:
                response["error"] = no_param_err
                response["error"]["message"] = response["error"]["message"].format("string")

        elif method == "getblockhash":
            height = self.get_rpc_param(request_data)

            if isinstance(height, int):
                if 0 <= height <= self.blocks.get(self.best_tip).get("height"):
                    response["result"] = nx.shortest_path(self.blockchain, self.genesis, self.best_tip)[height]

                else:
                    response["error"] = {"code": RPC_INVALID_PARAMETER, "message": "Block height out of range"}
            else:
                response["error"] = no_param_err
                response["error"]["message"] = response["error"]["message"].format("integer")

        elif method == "getbestblockhash":
            response["result"] = self.best_tip

        elif method == "help":
            pass

        else:
            return abort(404, "Method not found")

        return Response(json.dumps(response), status=200, mimetype="application/json")

    def in_best_chain(self, block_hash):
        """
        Returns whether a given block hash if part of the best chain or not. A block is party of the best chain if there
        a path from it to the best tip (directed graph).

        Args:
            block_hash(:obj:`str`): the block hash to be checked.

        Returns:
            :obj:`bool`: Whether the block is part of the best chain or not.
        """
        try:
            nx.shortest_path(self.blockchain, block_hash, self.best_tip)
            return True
        except NetworkXNoPath:
            return False

    def simulate_mining(self, verbose=True):
        """
        Simulates bicoin mining. The simulator ca be run in two modes: by events, or by time.

        If ``mode=='event'``, the simulator will be waiting for event on `/generate`. Otherwise, a block will be mined
        every ``TIME_BETWEEN_BLOCKS`` seconds. Transactions received via ``sendrawtransactions`` wil be included in a
        new generated block (up to ``TX_PER_BLOCK``).

        Also, the simulator will notify about new blocks via ZMQ.

        Args:
            verbose(:obj:`bool`): whether to print via stdout when a new block has been mined (including the txs).
        """

        mining_simulator = ZMQPublisher(
            topic=b"hashblock", feed_protocol=conf.FEED_PROTOCOL, feed_addr=conf.FEED_ADDR, feed_port=conf.FEED_PORT
        )

        while self.mine_new_block.wait():
            block_hash, coinbase_tx, coinbase_tx_hash = self.get_new_block_data()
            txs_to_mine = dict({coinbase_tx_hash: coinbase_tx})

            if len(self.mempool) != 0:
                # We'll mine up to TX_PER_BLOCK
                for txid, rawtx in dict(islice(self.mempool.items(), conf.TX_PER_BLOCK)).items():
                    txs_to_mine[txid] = rawtx
                    self.mempool.pop(txid)

            # Keep track of the mined transaction (to respond to getrawtransaction)
            for txid, tx in txs_to_mine.items():
                self.transactions[txid] = {"tx": tx, "block_hash": block_hash}

            # FIXME: chain_work is being defined as a incremental counter for now. Multiple chains should be possible.
            self.blocks[block_hash] = {
                "tx": list(txs_to_mine.keys()),
                "height": self.blocks[self.last_mined_block].get("height") + 1,
                "previousblockhash": self.last_mined_block,
                "chainwork": self.blocks[self.last_mined_block].get("height") + 1,
            }

            # Send data via ZMQ
            mining_simulator.publish_data(binascii.unhexlify(block_hash))

            # Add the block to the chain and update the tip
            self.blockchain.add_node(block_hash, short_id=block_hash[:8])
            self.blockchain.add_edge(self.last_mined_block, block_hash)

            # Update pointers
            self.last_mined_block = block_hash

            if self.blocks[block_hash].get("chainwork") > self.blocks[self.best_tip].get("chainwork"):
                self.best_tip = block_hash

            # Wait until new event
            self.mine_new_block.clear()

            if verbose:
                print("New block mined: {}".format(block_hash))
                print("\tTransactions: {}".format(list(txs_to_mine.keys())))

    def run(self, host=conf.BTC_RPC_HOST, port=conf.BTC_RPC_PORT, mode="time", verbose=True):
        """
        Runs the mock.

        The mock will be accessible at BTC_RPC_HOST:BTC_RPC_PORT (check sample_conf.py). By default if uses the same
        ports that bitcoind (both for RPC and ZMQ).

        Args:
            host(:obj:`str`): the host where the http server will run. Defaults to BTC_RPC_HOST.
            port(:obj:`int`): the port where the http server will run. Defaults to BTC_RPC_PORT.
            mode(:obj:`str`): the mode the simulator is running on. Can be either ``'time'`` or ``'event```.
            verbose(:obj:`bool`): whether to print via stdout when a new block has been mined (including the txs).

        """

        if mode not in ["time", "event"]:
            raise ValueError("Node must be time or event")

        # Define the API routes
        routes = {
            "/": (self.process_request, ["POST"]),
            "/generate": (self.generate, ["POST"]),
            "/fork": (self.create_fork, ["POST"]),
        }
        for url, params in routes.items():
            app.add_url_rule(url, view_func=params[0], methods=params[1])

        if mode == "time":
            Thread(target=set_event, args=[self.mine_new_block, conf.TIME_BETWEEN_BLOCKS]).start()

        mining_thread = Thread(target=self.simulate_mining, args=[verbose])
        mining_thread.start()

        # Setting Flask log to ERROR only so it does not mess with out logging. Also disabling flask initial messages
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        os.environ["WERKZEUG_RUN_MAIN"] = "true"

        app.run(host=host, port=port)
