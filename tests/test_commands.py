from dataclasses import dataclass

import pytest

from mega_cli.api import BaseCommand, Field
from mega_cli.api.errors import MegaProtocolError


@dataclass
class FooResponse:
    required: int = Field(api_alias="r")
    optional: str | None = Field(api_alias="o", default=None)


class Foo(BaseCommand[FooResponse], name="foo"):
    pass


# --- parse_response ---------------------------------------------------------------------------
def test_missing_required_field_raises_protocol_error() -> None:
    with pytest.raises(MegaProtocolError, match=r"'foo'.*missing required fields \['r'\]"):
        Foo.parse_response({"o": "x"})


def test_missing_optional_field_uses_default() -> None:
    assert Foo.parse_response({"r": 1}) == FooResponse(required=1, optional=None)


def test_non_object_response_raises_protocol_error() -> None:
    with pytest.raises(MegaProtocolError, match=r"Expected an object for 'foo'"):
        Foo.parse_response("unexpected")
