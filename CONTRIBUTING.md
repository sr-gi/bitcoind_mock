# Contributing to bitcoind_mock

The following is a set of guidelines for contributing to bitcoind_mock.

## Code Style Guidelines
We use [black](https://github.com/psf/black) as our base code formatter with a line length of 120 chars. Before submitting a PR make sure you have properly formatted your code by running:

```bash
black --line-length=120 {source_file_or_directory}
```
On top of that, there are a few rules to also have in mind.

### Code Spacing
Blocks of code should be created to separate logical sections

```python
# Create the genesis block
block_hash, coinbase_tx, coinbase_tx_hash = self.get_new_block_data()
self.transactions[coinbase_tx_hash] = {"tx": coinbase_tx, "block_hash": block_hash}

self.blocks[block_hash] = {
    "tx": [coinbase_tx_hash],
    "height": 0,
    "previousblockhash": GENESIS_PARENT,
    "chainwork": 0,
}
```
We favour spacing between blocks like `if/else`, `try/except`, etc.

```python
if txid not in self.transactions:
    self.mempool[txid] = rawtx
    response["result"] = {"txid": txid}

else:
    response["error"] = {
        "code": RPC_VERIFY_ALREADY_IN_CHAIN,
        "message": "Transaction already in block chain",
    }
```

An exception to the rule are nested `if` statements that placed right after each other and `if` statements with a single line of code.

```python
if self.in_best_chain(block_hash):
    block["confirmations"] = 1 + self.blocks.get(self.best_tip).get("height") - block.get("height")
else:
    block["confirmations"] = -1
```

## Code Documentation
Code should be, at least, documented using docstrings. We use the [Sphinx Google Style](https://www.sphinx-doc.org/en/master/usage/extensions/example_google.html#example-google) for documenting functions.

## Test Coverage
We use [pytest](https://docs.pytest.org/en/latest/) to build and run tests. Tests should be provided to cover both positive and negative conditions. Test should cover both the proper execution as well as all the covered error paths. PR with no proper test coverage will be rejected. 


