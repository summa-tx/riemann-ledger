from ether import transactions

from ledger import blue, utils

from typing import List
from ledger.ledger_types import LedgerPubkey
from ether.ether_types import SignedEthTx, UnsignedEthTx


def _parse_public_key_response(response: bytes) -> LedgerPubkey:
    '''
    Parse the Ledger's serializied key response into a data structure
    '''
    pubkey_len = response[0]
    pubkey = response[1:1 + pubkey_len]

    address_len = response[1 + pubkey_len]
    address_offset = 1 + pubkey_len + 1

    # 20 byte address, but it's utf8 encoded
    address_bytes = response[address_offset: address_offset + address_len]

    return LedgerPubkey(
        pubkey=bytes(pubkey),
        address=f'0x{address_bytes.decode("utf8")}')


async def get_key_info(client: blue.Ledger, derivation: str) -> LedgerPubkey:
    '''
    Fetch the pubkey at a specific derivation
    '''
    deriv_indices = utils.parse_derivation(derivation)
    derivation_data = blue.derivation_path_to_apdu_data(deriv_indices)

    pubkey_req_apdu = blue.make_apdu(
        command=b'\x02',  # ETH get key at derivation command
        p1=b'\x01',
        data=derivation_data
    )

    # It comes in a blob with chaincode and address
    pubkey_response = await client.exchange(pubkey_req_apdu)

    # return the parsed response
    pubkey = _parse_public_key_response(pubkey_response)
    return pubkey


async def get_app_version(client: blue.Ledger) -> List[int]:
    apdu = blue.make_apdu(command=b'\x06')
    result = await client.exchange(apdu)
    return [int(r) for r in result[1:]]


def _packetize_data(derivation_data: bytes, ser_tx: bytes) -> List[bytes]:
    # TODO: apdu size is capped at 64 bytes. so we need to chunk.
    #       continuation apdus have p1 set to 0x80
    #       p2 is still set to 0
    #       https://github.com/LedgerHQ/ledgerjs/blob/master/packages/hw-app-eth/src/Eth.js#L185-L190
    offset = 50 - len(derivation_data)
    remainder = ser_tx[offset:]

    first_chunk = derivation_data + ser_tx[:offset]

    chunks = [first_chunk]
    chunks.extend([remainder[i:i + 50] for i in range(0, len(remainder), 50)])

    # first chunk
    packets = [
        blue.make_apdu(
            command=b'\x04',
            data=chunks[0]
        )
    ]

    # other chunks
    for chunk in chunks[1:]:
        packet = blue.make_apdu(
            command=b'\x04',
            p1=b'\x80',
            data=chunk)
        packets.append(packet)

    return packets


async def sign_transaction(
        client: blue.Ledger,
        t: UnsignedEthTx,
        derivation: str) -> SignedEthTx:
    if (t['chainId'] * 2 + 35) + 1 > 255:
        raise ValueError('chainIds above 109 not currently supported.')

    deriv_indices = utils.parse_derivation(derivation)
    derivation_data = blue.derivation_path_to_apdu_data(deriv_indices)

    dummy_tx = SignedEthTx(
        to=t['to'],
        value=t['value'],
        gas=t['gas'],
        gasPrice=t['gasPrice'],
        nonce=t['nonce'],
        data=t['data'],
        v=t['chainId'], r=0, s=0)

    ser_tx = bytes.fromhex(transactions.serialize(dummy_tx))

    packets = _packetize_data(derivation_data, ser_tx)
    try:
        for packet in packets:
            result = await client.exchange(packet)
    except blue.LedgerException as e:
        if '6804' in str(e):
            details = 'Hint: is your derivation in the correct bip44 subtree?'
        if t['data'] == b'' or '6a80' not in str(e):
            raise e
        if t['gasPrice'] < 1000 or t['gas'] < 21000:
            details = 'Hint: gasPrice or gas too low?'
        else:
            details = 'Hint: enable data in the Ethereum app on the device?'
        raise blue.LedgerException(f'{str(e)}. {details}')

    v = result[0]
    r = int.from_bytes(result[1:33], 'big')
    s = int.from_bytes(result[33:65], 'big')

    signed = SignedEthTx(
        to=t['to'],
        value=t['value'],
        gas=t['gas'],
        gasPrice=t['gasPrice'],
        nonce=t['nonce'],
        data=t['data'],
        v=v, r=r, s=s)

    return signed
