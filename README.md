## riemann-ledger: sign transactions on a ledger

Async library for signing transactions on your Ledger Nano S.

Supports only native SegWit transactions

### Usage

You may need to install `libudev-dev` and/or `libusb-1.0-0-dev`

```python
import asyncio
import riemann
from ledger import blue

async def do_some_things():
    # set up the client
    await blue.make_client()
    derivation = 'm/44h/0h/0h/0/1'
    pubkey: bytes = await blue.get_uncompressed_public_key(derivation)
    xpub: str = await blue.get_xpub(derivation)

    t: riemann.tx.Tx = ...  # a riemann-tx native witness transaction
    prevouts: List[PrevoutInfo] = [...]  # datastructure in ledger.ledger_types

    # sign each input we can sign
    # return a list. Each entry is the signature bytes, or None if not signable
    sigs: List[Optional[str]] = await blue.get_tx_signatures(
        t=t,
        prevouts=prevouts,
        derivation=derivation)

asyncio.get_event_loop().run_until_complete(do_some_things())
```

### Development

You may need to install `libudev-dev` and/or `libusb-1.0-0-dev`

Clone the repo, then install dependencies with `pipenv install`

Run tests with `./run_tests.sh`. Right now this only runs the linter and mypy.
We'll write some tests soon
