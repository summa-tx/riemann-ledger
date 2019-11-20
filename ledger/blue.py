import asyncio

from riemann import tx
from riemann import utils as rutils
from riemann.encoding import base58

from ledgerblue.commException import CommException
from ledgerblue.comm import getDongle, Dongle

from ledger import utils

from ledger.ledger_types import LedgerPubkey, PrevoutInfo
from typing import cast, List, Optional, Tuple

# https://ledgerhq.github.io/btchip-doc/bitcoin-technical-beta.html

_CLIENT = None
SIGHASH_ALL = tx.shared.SIGHASH_ALL


class LedgerException(Exception):
    ...


async def make_client() -> Dongle:
    '''
    Sets up a new Ledger client and stores it as a singleton
    '''
    global _CLIENT

    if _CLIENT is None:
        try:
            _CLIENT = await utils.asyncify(getDongle, True)
        except CommException:
            raise RuntimeError('No device found')
        return _CLIENT
    else:
        return _CLIENT


async def _get_client() -> Dongle:
    '''Gets the singleton'''
    # TODO: check if it works and throw error if not

    while _CLIENT is None:
        await asyncio.sleep(5)
    return _CLIENT


async def _exchange(data: bytes) -> bytes:
    try:
        client = await _get_client()
        return bytes(await utils.asyncify(client.exchange, data))
    except Exception as e:
        raise LedgerException(str(e))


def _make_adpu(
        command: bytes,
        p1: bytes = b'\x00',
        p2: bytes = b'\x00',
        data: bytes = b'',
        response_len: int = 64) -> bytes:
    # https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
    adpu = (
        b'\xE0'     # CLA
        + command   # INS
        + p1        # p1
        + p2        # p2
        + rutils.i2be(len(data))  # LC
        + data
        + rutils.i2be(response_len))  # LE
    if len(adpu) > 64:
        raise ValueError('ADPU is too long')
    return adpu


def _derivation_path_to_adpu_data(path: List[int]) -> bytes:
    '''Convert a deriation path (as a list of integers) to a adpu data blob'''
    indices_blob = bytearray()

    if len(path) > 10:
        raise ValueError('Only 10 derivations allowed on Ledger')

    # convert each one into a BE number
    for index in path:
        indices_blob.extend(rutils.i2be_padded(index, 4))

    # we length prefix it with the number of derivations
    len_prefix = bytes([len(path)])
    return len_prefix + indices_blob


def _parse_public_key_response(response: bytes) -> LedgerPubkey:
    '''
    Parse the Ledger's serializied key response into a data structure
    '''
    pubkey_len = response[0]
    pubkey = response[1:1 + pubkey_len]
    address = response[1 + pubkey_len + 1:-32]
    chain_code = response[-32:]  # last 32 are chain_code
    return LedgerPubkey(
        pubkey=bytes(pubkey),
        address=address.decode('utf8'),
        chain_code=bytes(chain_code))


def _make_child_xpub(
        derivation: str,
        parent_or_none: Optional[LedgerPubkey],
        child: LedgerPubkey,
        mainnet: bool = True) -> str:
    '''
    Builds an xpub for a derived child using its parent and path
    Args:
        derivation      (str): the m-prefixed derivation path e.g. m/44h/0h/0h
        parent (LedgerPubkey): the parent public key
        child  (LedgerPubkey): the child public key
        mainnet        (bool): whether to use mainnet prefixes
    '''
    indices = utils.parse_derivation(derivation)

    # determine appropriate xpub version bytes
    if not mainnet:
        prefix = utils.VERSION_BYTES['testnet']['public']
    else:
        prefix = utils.VERSION_BYTES['mainnet']['public']

    if parent_or_none is not None:
        # xpubs include the parent fingerprint
        parent = cast(LedgerPubkey, parent_or_none)
        compressed_parent_key = utils.compress_pubkey(parent['pubkey'])
        parent_fingerprint = rutils.hash160(compressed_parent_key)[:4]
        child_index = indices[-1].to_bytes(4, byteorder='big')
        depth = len(indices)
    else:
        # this means it's a master key
        parent_fingerprint = b'\x00' * 4
        child_index = b'\x00' * 4
        depth = 0

    # xpubs always use compressed pubkeys
    compressed_pubkey = utils.compress_pubkey(child['pubkey'])

    # build the xpub
    xpub = bytearray()
    xpub.extend(prefix)                      # xpub prefix
    xpub.extend([depth])                     # depth
    xpub.extend(parent_fingerprint)          # paren't fingerprint
    xpub.extend(child_index)                 # index
    xpub.extend(child['chain_code'])         # chain_code
    xpub.extend(compressed_pubkey)           # pubkey (comp)
    return base58.encode(xpub)


async def _get_key_info(derivation: str) -> LedgerPubkey:
    '''
    This corresponds to the GET WALLET PUBLIC KEY command
    It asks the ledger for the key at a derivation path
    Args:
        derivation (str): the derivatoin path string
    Returns:
        (LedgerPubkey): The parsed public key with type, address and chain_code
    '''
    # first we get the path into a form that the ledger can understand
    deriv_indices = utils.parse_derivation(derivation)

    # make the adpu formatted request body
    pubkey_adpu_data = _derivation_path_to_adpu_data(deriv_indices)
    pubkey_adpu = _make_adpu(
        command=b'\x40',
        data=pubkey_adpu_data,
        p2=b'\x02')  # native segwit address

    # It comes in a blob with chaincode and address
    pubkey_response = await _exchange(pubkey_adpu)

    # return the parsed response
    pubkey = _parse_public_key_response(pubkey_response)
    return pubkey


async def get_uncompressed_public_key(derivation: str) -> bytes:
    '''Get the public key for a derivation'''
    pubkey = await _get_key_info(derivation)
    return pubkey['pubkey']


async def get_xpub(derivation: str, mainnet: bool = True) -> str:
    '''
    Gets the xpub at a derivation path
    '''
    if derivation == 'm':
        parent = None
    else:
        # this looks like magic, but just pops the last derivation off
        parent_derivation = '/'.join(derivation.split('/')[:-1])
        parent = await _get_key_info(parent_derivation)

    child = await _get_key_info(derivation)

    # make the xpub for the child and instantiate an object
    xpub = _make_child_xpub(derivation, parent, child, mainnet)
    return xpub


def _transaction_start_packet(chunk: bytes) -> bytes:
    '''make UNTRUSTED HASH TRANSACTION INPUT START beginning adpu'''
    return _make_adpu(
        command=b'\x44',
        p1=b'\x00',
        p2=b'\x02',
        data=chunk)


def _transaction_continue_packet(chunk: bytes) -> bytes:
    '''make UNTRUSTED HASH TRANSACTION INPUT START continuation adpu'''
    return _make_adpu(
        command=b'\x44',
        p1=b'\x80',
        p2=b'\x02',
        data=chunk)


def _output_continue_packet(chunk: bytes) -> bytes:
    '''UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL non-final packet'''
    return _make_adpu(
        command=b'\x4a',
        data=chunk)


def _output_final_packet(chunk: bytes) -> bytes:
    '''UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL last packet'''
    return _make_adpu(
        command=b'\x4a',
        p1=b'\x80',
        data=chunk)


def _packetize_version_and_vin_length(t: tx.Tx) -> bytes:
    '''The first packet sent to UNTRUSTED HASH TRANSACTION INPUT START'''
    # will break on bullshit like non-compact VarInts
    chunk = t.version + tx.VarInt(len(t.tx_ins)).to_bytes()
    return _transaction_start_packet(chunk)


def _packetize_input(tx_in: tx.TxIn, prevout_info: PrevoutInfo) -> List[bytes]:
    '''Turn an input into a set of packets for tx prep'''
    if tx_in.script_sig != b'':
        raise NotImplementedError('Only native SegWit')
    le_value = rutils.i2le_padded(prevout_info['value'], 8)

    chunks = []

    # 02 for segwit, then the outpoint,
    # then the I64 value, then 0 for len(script)
    chunks.append(b'\x02' + tx_in.outpoint.to_bytes() + le_value + b'\x00')
    chunks.append(tx_in.sequence)

    return [_transaction_continue_packet(chunk) for chunk in chunks]


def _packetize_input_for_signing(
        tx_in: tx.TxIn,
        prevout_info: PrevoutInfo) -> List[bytes]:
    '''Turn an input into a set of packets for the last step of signing'''
    chunks = []
    if prevout_info['witness_script'] is None:
        raise ValueError('Packet for signing must have a script')
    script = cast(bytes, prevout_info['witness_script'])
    le_value = rutils.i2le_padded(prevout_info['value'], 8)

    script_len_bytes = tx.VarInt(len(script)).to_bytes()

    # the first packt is the outpoint and value
    chunks.append(b'\x02'  # 02 is ledger-speak for segwit input
                  + tx_in.outpoint.to_bytes()
                  + le_value
                  + script_len_bytes)

    # Chunk into 50-byte chunks
    chunks.extend([script[i:i + 50] for i in range(0, len(script), 50)])

    # append the sequence to the last one
    chunks[-1] = chunks[-1] + tx_in.sequence

    return [_transaction_continue_packet(chunk) for chunk in chunks]


def _packetize_vout(tx_outs: Tuple[tx.TxOut, ...]) -> List[bytes]:
    '''Converts the output vector into adpu packets'''
    # first get the whole length-prefixed vector
    data_to_be_chunked = bytearray()
    data_to_be_chunked.extend(tx.VarInt(len(tx_outs)).to_bytes())
    for tx_out in tx_outs:
        data_to_be_chunked.extend(tx_out.to_bytes())

    # chunk it into 50 byte chunks
    chunks = [data_to_be_chunked[i:i + 50]  # chunk the data
              for i in range(0, len(data_to_be_chunked), 50)]

    # make continue packets for all but the last one
    packets = []
    packets.extend([_output_continue_packet(chunk) for chunk in chunks[:-1]])

    # the last one is a final packet
    packets.append(_output_final_packet(chunks[-1]))

    # return all the adpu packets
    return packets


def _transaction_final_packet(
        lock_time: bytes,
        path: List[int],
        sighash_type: int) -> bytes:
    '''
    UNTRUSTED HASH SIGN packet with locktime and sighash type
    This packet actually requests the sig

    Args:
        lock_time  (bytes): 4 byte LE-encoded locktime field
        path   (List[int]): list of derivation indices
        sighash_type (int): bitcoin consensus sighash type. NONE not supported
    Returns:
        (bytes): the adpu packet
    '''
    data = bytearray()
    data.extend(_derivation_path_to_adpu_data(path))  # derivation info
    data.extend(b'\x00')                              # user validation code ??
    data.extend(lock_time)
    data.append(sighash_type)
    return _make_adpu(
        command=b'\x48',
        data=data)


async def _get_sig(
        first_packet: bytes,
        last_packet: bytes,
        tx_in: tx.TxIn,
        prevout_info: PrevoutInfo) -> bytes:
    '''
    Gets a signature for an input
    Args:
        first_packet       (bytes): the first packet e0440000... (input start)
        last_packet        (bytes): the last packet e0480000... (hash sign)
        tx_in            (tx.TxIn): the transaction input
        prevout_info (PrevoutInfo): the script and value of the prevout
    Returns:
        (bytes): the signature, unmasked
    '''
    # for convenience, we do surgery on the packet
    # setting p1 and p2 to 0x0080 means this is a new pseudo-tx continuation
    # setting the second-to-last to 1 to overwrite len(vin)
    first_packet = (first_packet[0:2] + b'\x00\x80'
                    + first_packet[4:-2] + b'\x01' + first_packet[-1:])

    # they need to be packetized with their witness script
    input_packets = _packetize_input_for_signing(tx_in, prevout_info)

    # Send all the packets and the sig-request packet
    await(_exchange(first_packet))
    for packet in input_packets:
        await _exchange(packet)
    response = await _exchange(last_packet)  # request the sig

    # unmask the sig before we return it
    return _unmask_sig(response)


def _signable(
        key: bytes,
        prevout_info: PrevoutInfo) -> bool:
    '''
    Determines if the key or its hash is in the PrevoutInfo
    We use this to determine whether we should get a signature for an input

    Args:
        key                (bytes): the public key
        prevout_info (PrevoutInfo): dict of script and value for the prevout
    Returns:
        (bool): True if signable, false otherwise
    '''
    if len(key) in [64, 65]:
        key = utils.compress_pubkey(key)  # enforce compression

    # if there's no script, it's not signable
    if prevout_info['witness_script'] is None:
        return False

    # if the key is anywhere in the script, it is signable
    script = cast(bytes, prevout_info['witness_script'])
    if (key in script or rutils.hash160(key) in script):
        return True

    return False


def _unmask_sig(sig: bytes) -> bytes:
    '''Ledger masks the first byte with 0xFE. We need to remove the mask'''
    first_byte = sig[0] & 0xfe
    sig = bytes([first_byte]) + sig[1:]
    return sig


async def get_tx_signatures(
        t: tx.Tx,
        prevouts: List[PrevoutInfo],
        derivation: str,
        sighash_type: int = SIGHASH_ALL) -> List[Optional[bytes]]:
    '''
    Sign a transaction
    Args:
        t                    (tx.Tx): The transaction to sign
        prevouts (List[PrevoutInfo]): value for each Prevout
            must include the script if we intend to sign the input
            script must NOT be length-prefixed (e.g. 76a914... NOT 1976a914...)
        derivation             (str): m-prefixed derication for the signing key
        sighash_type           (int): Bitcoin-consensus sighash type, ledger
            firmware currently only supports ALL
    Returns:
        List[Optional[bytes]]: For each input, either a signature or None
    '''
    if len(prevouts) != len(t.tx_ins):
        raise ValueError('mismatch between txins and prevouts')

    if sighash_type != SIGHASH_ALL:
        raise ValueError('ledger firmware only supports SIGHASH_ALL')

    # Let's get the key so we can scan scripts for it
    key = await get_uncompressed_public_key(derivation)

    # start by packetizing version and len(vin)
    first_packet = _packetize_version_and_vin_length(t)
    packets = [first_packet]  # collect a list of packets for sending later

    # packetize each input
    for pair in zip(t.tx_ins, prevouts):
        packets.extend(_packetize_input(*pair))

    # packetize the whole vout
    packets.extend(_packetize_vout(t.tx_outs))

    # send all vin/vout packets
    for packet in packets:
        await _exchange(packet)

    # calculate the request packet
    indices = utils.parse_derivation(derivation)
    last_packet = _transaction_final_packet(t.lock_time, indices, sighash_type)

    # build sigs. If we're not signing the input, return None at its index
    sigs = []
    for pair in zip(t.tx_ins, prevouts):
        sigs.append(await _get_sig(first_packet, last_packet, *pair)
                    if _signable(key, pair[1])
                    else None)

    return sigs
