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


# --- secrets in error messages ----------------------------------------------------------------
SECRET = "SeCrEtKeY-do-not-leak"


def test_missing_field_error_lists_keys_but_not_values() -> None:
    with pytest.raises(MegaProtocolError) as exc:
        Foo.parse_response({"o": SECRET, "k": SECRET})

    message = str(exc.value)
    assert "got keys ['k', 'o']" in message
    assert SECRET not in message


def test_non_object_error_names_type_but_not_value() -> None:
    with pytest.raises(MegaProtocolError) as exc:
        Foo.parse_response([SECRET])

    message = str(exc.value)
    assert message.endswith("got list")
    assert SECRET not in message


def test_long_secret_does_not_leak_partially() -> None:
    long_secret = "A" * 300
    with pytest.raises(MegaProtocolError) as exc:
        Foo.parse_response({"privk": long_secret})

    assert "A" * 20 not in str(exc.value)
