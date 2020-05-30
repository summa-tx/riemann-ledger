from riemann import utils as rutils
from ledgerblue.comm import getDongle, Dongle
from ledgerblue.commException import CommException

from ledger import utils

from typing import Any, List


class LedgerException(Exception):
    ...


class Ledger:
    '''
    A simple wrapper around the ledgerblue Dongle object.
    It provides a context manager, as well as passthrough functions
    '''
    client: Dongle = None
    debug: bool

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.client = None

    def open(self):
        self.client = getDongle(self.debug)

    def close(self) -> None:
        self.client.device.close()
        self.client = None

    def __enter__(self) -> 'Ledger':
        try:
            self.open()
            return self
        except CommException:
            raise RuntimeError('No device found')

    async def __aenter__(self) -> 'Ledger':
        return self.__enter__()

    def __exit__(self, *args: Any) -> None:
        self.close()

    async def __aexit__(self, *args: Any) -> None:
        self.close()

    def exchange_sync(self, data: bytes):
        '''Synchronous exchange'''
        try:
            return self.client.exchange(data)
        except Exception as e:
            raise LedgerException(str(e))

    async def exchange(self, data: bytes) -> bytes:
        '''Asynchronous exchange'''
        return bytes(await utils.asyncify(self.exchange_sync, data))


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
        raise ValueError('APDU is too long')
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
