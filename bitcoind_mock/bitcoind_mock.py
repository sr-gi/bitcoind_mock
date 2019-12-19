import os
import time
import json
import logging
import binascii
import networkx as nx
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


class BitcoindMock:
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
            "chainwork": "{:x}".format(0),
        }
        self.blockchain.add_node(block_hash, short_id=block_hash[:8])
        self.best_tip = block_hash
        self.genesis = block_hash

        # Set the event so it can start mining right off the bat
        self.mine_new_block.set()

    @staticmethod
    def get_rpc_param(request_data):
        params = request_data.get("params")

        if isinstance(params, list) and len(params) > 0:
            return params[0]
        else:
            return None

    @staticmethod
    def get_new_block_data():
        block_hash = os.urandom(32).hex()
        coinbase_tx = TX.create_dummy_transaction()
        coinbase_tx_hash = sha256d(coinbase_tx)

        return block_hash, coinbase_tx, coinbase_tx_hash

    def generate(self):
        self.mine_new_block.set()

        return Response(status=200, mimetype="application/json")

    def create_fork(self):
        """
        create_fork processes chain fork requests. It will create a fork with the following parameters:
        parent: the block hash from where the chain will be forked
        length: the length of the fork to be created (number of blocks to be mined on top of parent)
        stay: whether to stay in the forked chain after length blocks has been mined or to come back to the previous chain.
              Stay is optional and will default to False.
        """

        request_data = request.get_json()
        response = {"result": 0, "error": None}

        parent = request_data.get("parent")

        # FIXME: We only accept forks one by one for now

        if parent not in self.blocks:
            response["error"] = {"code": -1, "message": "Wrong parent block to fork from"}

        else:
            self.best_tip = parent
            print("Forking chain from {}".format(parent))

        return Response(json.dumps(response), status=200, mimetype="application/json")

    def process_request(self):
        """
        process_requests simulates the bitcoin-rpc server run by bitcoind. The available commands are limited to the
        ones we'll need to use in pisa. The model we will be using is pretty simplified to reduce the complexity of
        simulating bitcoind:

        Raw transactions:       raw transactions will actually be transaction ids (txids). Pisa will, therefore, receive
                                encrypted blobs that encrypt ids instead of real transactions.

        decoderawtransaction:   querying for the decoding of a raw transaction will return a dictionary with a single
                                field: "txid", which will match with the txid provided in the request

        sendrawtransaction:     sending a rawtransaction will notify our mining simulator to include such transaction in
                                a subsequent block.

        getrawtransaction:      requesting a rawtransaction from a txid will return a dictionary containing a single
                                field: "confirmations", since rawtransactions are only queried to check whether a
                                transaction has made it to a block or not.

        getblockcount:          the block count will be get from the mining simulator by querying how many blocks have
                                been emitted so far.

        getblock:               querying for a block will return a dictionary with a three fields: "tx" representing a
                                list of transactions, "height" representing the block height and "hash" representing the
                                block hash. Both will be got from the mining simulator.

        getblockhash:           a block hash is only queried by pisad on bootstrapping to check the network bitcoind is
                                running on.

        getbestblockhash:       returns the hash of the block in the tip of the chain

        help:                   help is only used as a sample command to test if bitcoind is running when bootstrapping
                                pisad. It will return a 200/OK with no data.
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
                            "confirmations": self.blocks.get(self.best_tip).get("height") - block.get("height"),
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
                block = self.blocks.get(block_hash)

                if block is not None:
                    if self.in_best_chain(block_hash):
                        block["confirmations"] = self.blocks.get(self.best_tip).get("height") - block.get("height")
                    else:
                        block["confirmations"] = -1

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
        A block is party of the best chain if there a path from it to the best tip (directed graph).
        """
        try:
            nx.shortest_path(self.blockchain, block_hash, self.best_tip)
            return True
        except NetworkXNoPath:
            return False

    def simulate_mining(self, mode, time_between_blocks, verbose=True):
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
                "height": self.blocks[self.best_tip].get("height") + 1,
                "previousblockhash": self.best_tip,
                "chainwork": "{:x}".format(self.blocks[self.best_tip].get("height") + 1),
            }

            # Send data via ZMQ
            mining_simulator.publish_data(binascii.unhexlify(block_hash))

            # Add the block to the chain and update the tip
            self.blockchain.add_node(block_hash, short_id=block_hash[:8])
            self.blockchain.add_edge(self.best_tip, block_hash)
            self.best_tip = block_hash

            if verbose:
                print("New block mined: {}".format(block_hash))
                print("\tTransactions: {}".format(list(txs_to_mine.keys())))

            if mode == "time":
                time.sleep(time_between_blocks)

            else:
                self.mine_new_block.clear()

    def run(self, mode="time", time_between_blocks=conf.TIME_BETWEEN_BLOCKS, verbose=True):
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

        mining_thread = Thread(target=self.simulate_mining, args=[mode, time_between_blocks, verbose])
        mining_thread.start()

        # Setting Flask log to ERROR only so it does not mess with out logging. Also disabling flask initial messages
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        os.environ["WERKZEUG_RUN_MAIN"] = "true"

        app.run(host=conf.BTC_RPC_HOST, port=conf.BTC_RPC_PORT)
