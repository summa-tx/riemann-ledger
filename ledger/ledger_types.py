from typing import Optional
from mypy_extensions import TypedDict


class LedgerPubkey(TypedDict):
    pubkey: bytes
    address: str
    chain_code: bytes


class PrevoutInfo(TypedDict):
    value: int
    witness_script: Optional[bytes]
