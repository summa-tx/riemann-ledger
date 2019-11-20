import asyncio
from functools import partial

from typing import Any, Awaitable, Callable, List

BIP32_HARDEN = 0x80000000

# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
VERSION_BYTES = {
    'mainnet': {
        'public': b'\x04\x88\xb2\x1e',
        'private': b'\x04\x88\xad\xe4',
    },
    'testnet': {
        'public': b'\x04\x35\x87\xcf',
        'private': b'\x04\x35\x83\x94',
    }
}


def asyncify(function: Callable, *args: Any, **kwargs: Any) -> Awaitable:
    '''
    Turns a synchronous function into a future
    '''
    loop = asyncio.get_event_loop()
    p = partial(function, *args, **kwargs)
    return loop.run_in_executor(None, p)


def parse_derivation(derivation_path: str) -> List[int]:
    '''
    turns a derivation path (e.g. m/44h/0) into a list of integer indexes
        e.g. [2147483692, 0]
    Args:
        derivation_path (str): the human-readable derivation path
    Returns:
        (list(int)): the derivaion path as a list of indexes
    '''
    int_nodes: List[int] = []

    # Must be / separated
    nodes: List[str] = derivation_path.split('/')
    # If the first node is not m, error.
    # TODO: allow partial path knowledge
    if nodes[0] != 'm':
        raise ValueError('Bad path. Got: {}'.format(derivation_path))
    if len(nodes) == 1:
        return []
    # Go over all other nodes, and convert to indexes
    nodes = nodes[1:]
    for i in range(len(nodes)):
        if nodes[i][-1] in ['h', "'"]:  # Support 0h and 0' conventions
            int_nodes.append(int(nodes[i][:-1]) + BIP32_HARDEN)
        else:
            int_nodes.append(int(nodes[i]))
    return int_nodes


def compress_pubkey(pubkey: bytes) -> bytes:
    if len(pubkey) == 65:
        pubkey = pubkey[1:]
    if len(pubkey) != 64:
        raise ValueError('Pubkey must be 64 or 65 bytes')

    if pubkey[-1] & 1:
        return b'\x03' + pubkey[:32]
    else:
        return b'\x02' + pubkey[:32]
