import asyncio
from functools import partial

from riemann import utils as rutils
from riemann.encoding import base58

from ledger.ledger_types import LedgerPubkey, LedgerXPub
from typing import Any, Awaitable, cast, Callable, List, Optional

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


def make_child_xpub(
        derivation: str,
        parent_or_none: Optional[LedgerXPub],
        child: LedgerXPub,
        mainnet: bool = True) -> str:
    '''
    Builds an xpub for a derived child using its parent and path
    Args:
        derivation      (str): the m-prefixed derivation path e.g. m/44h/0h/0h
        parent (LedgerPubkey): the parent public key
        child  (LedgerPubkey): the child public key
        mainnet        (bool): whether to use mainnet prefixes
    '''
    indices = parse_derivation(derivation)

    # determine appropriate xpub version bytes
    if not mainnet:
        prefix = VERSION_BYTES['testnet']['public']
    else:
        prefix = VERSION_BYTES['mainnet']['public']

    if parent_or_none is not None:
        # xpubs include the parent fingerprint
        parent = cast(LedgerPubkey, parent_or_none)
        compressed_parent_key = compress_pubkey(parent['pubkey'])
        parent_fingerprint = rutils.hash160(compressed_parent_key)[:4]
        child_index = indices[-1].to_bytes(4, byteorder='big')
        depth = len(indices)
    else:
        # this means it's a master key
        parent_fingerprint = b'\x00' * 4
        child_index = b'\x00' * 4
        depth = 0

    # xpubs always use compressed pubkeys
    compressed_pubkey = compress_pubkey(child['pubkey'])

    # build the xpub
    xpub = bytearray()
    xpub.extend(prefix)                      # xpub prefix
    xpub.extend([depth])                     # depth
    xpub.extend(parent_fingerprint)          # paren't fingerprint
    xpub.extend(child_index)                 # index
    xpub.extend(child['chain_code'])         # chain_code
    xpub.extend(compressed_pubkey)           # pubkey (comp)
    return base58.encode(xpub)
