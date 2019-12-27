from riemann import tx
from riemann import utils as rutils

from ledger import blue, utils

from typing import cast, List, Optional, Tuple
from ledger.ledger_types import LedgerXPub, PrevoutInfo

# https://ledgerhq.github.io/btchip-doc/bitcoin-technical-beta.html


SIGHASH_ALL = tx.shared.SIGHASH_ALL


def _parse_public_key_response(response: bytes) -> LedgerXPub:
    '''
    Parse the Ledger's serializied key response into a data structure
    '''
    pubkey_len = response[0]
    pubkey = response[1:1 + pubkey_len]
    address = response[1 + pubkey_len + 1:-32]
    chain_code = response[-32:]  # last 32 are chain_code
    return LedgerXPub(
        pubkey=bytes(pubkey),
        address=address.decode('utf8'),
        chain_code=bytes(chain_code))


async def get_key_info(client: blue.Ledger, derivation: str) -> LedgerXPub:
    '''
    This corresponds to the GET WALLET PUBLIC KEY command
    It asks the ledger for the key at a derivation path
    Args:
        derivation (str): the derivatoin path string
    Returns:
        (LedgerXPub): The parsed public key with type, address and chain_code
    '''
    # first we get the path into a form that the ledger can understand
    deriv_indices = utils.parse_derivation(derivation)

    # make the apdu formatted request body
    derivation_data = blue.derivation_path_to_apdu_data(deriv_indices)
    pubkey_req_apdu = blue.make_apdu(
        command=b'\x40',
        data=derivation_data,
        p2=b'\x02')  # native segwit address

    # It comes in a blob with chaincode and address
    pubkey_response = await client.exchange(pubkey_req_apdu)

    # return the parsed response
    pubkey = _parse_public_key_response(pubkey_response)
    return pubkey


async def get_uncompressed_public_key(
        client: blue.Ledger, derivation: str) -> bytes:
    '''Get the public key for a derivation'''
    pubkey = await get_key_info(client, derivation)
    return pubkey['pubkey']


async def get_xpub(
        client: blue.Ledger,
        derivation: str,
        mainnet: bool = True) -> str:
    '''
    Gets the xpub at a derivation path
    '''
    if derivation == 'm':
        parent = None
    else:
        # this looks like magic, but just pops the last derivation off
        parent_derivation = '/'.join(derivation.split('/')[:-1])
        parent = await get_key_info(client, parent_derivation)

    child = await get_key_info(client, derivation)

    # make the xpub for the child and instantiate an object
    xpub = utils.make_child_xpub(derivation, parent, child, mainnet)
    return xpub


def _transaction_start_packet(chunk: bytes) -> bytes:
    '''make UNTRUSTED HASH TRANSACTION INPUT START beginning apdu'''
    return blue.make_apdu(
        command=b'\x44',
        p1=b'\x00',
        p2=b'\x02',
        data=chunk)


def _transaction_continue_packet(chunk: bytes) -> bytes:
    '''make UNTRUSTED HASH TRANSACTION INPUT START continuation apdu'''
    return blue.make_apdu(
        command=b'\x44',
        p1=b'\x80',
        p2=b'\x02',
        data=chunk)


def _output_continue_packet(chunk: bytes) -> bytes:
    '''UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL non-final packet'''
    return blue.make_apdu(
        command=b'\x4a',
        data=chunk)


def _output_final_packet(chunk: bytes) -> bytes:
    '''UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL last packet'''
    return blue.make_apdu(
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
    '''Converts the output vector into apdu packets'''
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

    # return all the apdu packets
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
        (bytes): the apdu packet
    '''
    data = bytearray()
    data.extend(blue.derivation_path_to_apdu_data(path))  # derivation info
    data.extend(b'\x00')                              # user validation code ??
    data.extend(lock_time)
    data.append(sighash_type)
    return blue.make_apdu(
        command=b'\x48',
        data=data)


async def _get_sig(
        client: blue.Ledger,
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
    # yes, this is messy. but it's way more straightforward than
    # setting p1 and p2 to 0x0080 means this is a new pseudo-tx continuation
    # setting the second-to-last to 1 to overwrite len(vin)
    first_packet = (first_packet[0:2]
                    + b'\x00\x80'  # overwrite p1+p2
                    + first_packet[4:-2]
                    + b'\x01'      # overwrite len(vin)
                    + first_packet[-1:])

    # they need to be packetized with their witness script
    input_packets = _packetize_input_for_signing(tx_in, prevout_info)

    # Send all the packets and the sig-request packet
    await client.exchange(first_packet)
    for packet in input_packets:
        await client.exchange(packet)
    response = await client.exchange(last_packet)  # request the sig

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
        client: blue.Ledger,
        t: tx.Tx,
        prevouts: List[PrevoutInfo],
        derivation: str,
        sighash_type: int = SIGHASH_ALL) -> List[Optional[bytes]]:
    '''
    Sign a transaction
    Args:
        client              (Ledger): the Ledger context manager object
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
    key = await get_uncompressed_public_key(client, derivation)

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
        await client.exchange(packet)

    # calculate the request packet
    indices = utils.parse_derivation(derivation)
    last_packet = _transaction_final_packet(t.lock_time, indices, sighash_type)

    # build sigs. If we're not signing the input, return None at its index
    sigs = []
    for pair in zip(t.tx_ins, prevouts):
        sigs.append(await _get_sig(client, first_packet, last_packet, *pair)
                    if _signable(key, pair[1])
                    else None)

    return sigs
