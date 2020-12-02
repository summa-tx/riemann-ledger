## riemann-ledger: sign transactions on a ledger

Py37+ library for signing transactions on your Ledger hardware wallet.

Supports Native Segwit BTC transactions (`riemann-tx`), and Ethereum
transactions (`riemann-ether`). Check those libraries for documentation of the
transaction format.

### Usage

You may need to install `libudev-dev` and/or `libusb-1.0-0-dev`.

If a function needs to communicate with the device, the client object is passed
as the first argument.

We recommend using the hardware client as a context manager, although you can
also manage its lifecycle by calling `open` and `close`.


### Example

```python
import asyncio

from riemann.tx import Tx as BitcoinTx
from ether.ether_types import UnsignedEthTx

from ledger import blue, btc, eth

derivation = 'm/44h/0h/0h/0/1'
# for Eth, make sure to use `m/44h/60h/0h/0/0`

async def recommended_pattern():
    # Recommended: use the client as a context manager
    async with blue.Ledger() as client:
        # Open the BTC app on the device
        xpub = await btc.get_xpub(client, derivation)

        t: BitcoinTx = ...          # a riemann-tx native witness transaction
        prevouts: List[PrevoutInfo] = [...]  # defined in ledger.ledger_types

        # sign each input we can sign
        # return a list. Each entry is the signature bytes. None if un-signable
        sigs: List[Optional[str]] = await btc.get_tx_signatures(
            client=client,
            t=t,
            prevouts=prevouts,
            derivation=derivation)

        # Switch to the Ethereum app on the device
        # ethereum key info
        key = await eth.get_key_info(client, derivation)

        # also sign an ethereum txn
        eth_tx = UnsignedEthTx(...)
        signed_eth_tx = await eth.sign_transaction(client, eth_tx, derivation)


def as_an_object_sync():
    # use the client as an object
    client = blue.Ledger()
    client.open()

    # higher-level methods assume async
    # the sync exchange is only useful for low-level communication
    client.exchange_sync(...)

    # if you don't close it, future open() calls on other objects will error
    client.close()

```

### Development

You may need to install `libudev-dev` and/or `libusb-1.0-0-dev`

Clone the repo, then install dependencies with `pipenv install`

Run tests with `./run_tests.sh`. Right now this only runs the linter and mypy.
We'll write some tests soon


### Tests

`./run_tests.sh` will run the linter and type checker. We currently do not have
unit tests.
