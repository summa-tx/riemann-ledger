import asyncio

from riemann import utils as rutils
from ledgerblue.comm import getDongle, Dongle
from ledgerblue.commException import CommException

from ledger import utils

from typing import List

_CLIENT = None


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


async def get_client() -> Dongle:
    '''Gets the singleton'''
    # TODO: check if it works and throw error if not

    while _CLIENT is None:
        await asyncio.sleep(5)
    return _CLIENT


async def close() -> None:
    global _CLIENT

    if _CLIENT is None:
        return
    _CLIENT.device.close()
    _CLIENT = None


async def exchange(data: bytes) -> bytes:
    try:
        client = await get_client()
        return bytes(await utils.asyncify(client.exchange, data))
    except Exception as e:
        raise LedgerException(str(e))


def make_apdu(
        command: bytes,
        p1: bytes = b'\x00',
        p2: bytes = b'\x00',
        data: bytes = b'',
        response_len: int = 64) -> bytes:
    # https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
    apdu = (
        b'\xE0'     # CLA
        + command   # INS
        + p1        # p1
        + p2        # p2
        + rutils.i2be(len(data))  # LC
        + data
        + rutils.i2be(response_len))  # LE
    if len(apdu) > 64:
        raise ValueError('ADPU is too long')
    return apdu


def derivation_path_to_apdu_data(path: List[int]) -> bytes:
    '''Convert a deriation path (as a list of integers) to a apdu data blob'''
    indices_blob = bytearray()

    if len(path) > 10:
        raise ValueError('Only 10 derivations allowed on Ledger')

    # convert each one into a BE number
    for index in path:
        indices_blob.extend(rutils.i2be_padded(index, 4))

    # we length prefix it with the number of derivations
    len_prefix = bytes([len(path)])
    return len_prefix + indices_blob
