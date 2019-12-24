# bitcoind mock

[![tippin.me](https://badgen.net/badge/%E2%9A%A1%EF%B8%8Ftippin.me/@sr_gi/F0918E)](https://tippin.me/@sr_gi)

bitcoind mock is an approach to simulate bitcoind for unit testing. It is specially useful for `Continuous integration 
(CI)` tools. 

The mock provides a `JSON-RPC` interface with some of the RPC commands available in `bitcoind` along with a `zmq` 
interface for transaction and block notification. The mock also provides additional endpoints to generate blocks on 
demand (`/generate`) and to create forks (`/fork`).

The mock can be run either by `time`, where blocks will be generated in fix time intervals, or by `events` where a block
will be generated each time `/generate` is called.

This are the current partially covered commands:

```
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
```

## Known limitations

- The implemented commands do not return every single field that `bitcoind` would, only the most important ones (or the 
ones that I've required so for my own unit tests).

- The mock works well when interacting with via `python` but not if queried directly by `bitcoin-cli` (check [#1](https://github.com/sr-gi/bitcoind_mock/issues/1)).

- `zmq` only notifies about blocks being mined, but not about transactions.

- Requesting a fork while running the mock by `time` will not reset the timer for the block that will be mined on top of
the forked one.

### Dependencies

Refer to [DEPENCENCIES.md](DEPENDENCIES.md)

### Installation

Refer to [INSTALL.md](INSTALL.md)

### Contributing

If you'd like to add / extend any command, feel free to send a PR. We can make this as complete as we'd like by joining 
efforts :smile:
