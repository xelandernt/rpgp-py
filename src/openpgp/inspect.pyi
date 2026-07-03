
from typing import Optional, TypeAlias

Headers: TypeAlias = dict[str, list[str]]


class MessageInfo:
    @property
    def kind(self) -> str: ...
    @property
    def is_nested(self) -> bool: ...
    @property
    def headers(self) -> Optional[Headers]: ...


def inspect_message(data: str) -> MessageInfo: ...
def inspect_message_bytes(data: bytes) -> MessageInfo: ...
