import dataclasses
from dataclasses import dataclass
from types import get_original_bases
from typing import Any, ClassVar, dataclass_transform, get_args


# noinspection pep8-naming
def Field(*, api_alias: str | None = None, **kwargs: Any) -> Any:
    metadata = kwargs.pop("metadata", {})
    if api_alias:
        metadata["api_alias"] = api_alias

    return dataclasses.field(metadata=metadata, **kwargs)


@dataclass_transform(
    kw_only_default=True, frozen_default=True, field_specifiers=(dataclasses.field, Field)
)  # For type checkers and IDEs, so they know how subclasses should behave
class BaseCommand[Response = Any]:
    """Every command MEGA understands has this shared structure"""

    name: ClassVar[str]
    """The command name, sent as the ``a`` field"""

    response_type: ClassVar[Any]
    """The ``X`` in ``BaseCommand[X]``, or ``None``"""

    def __init_subclass__(cls, *, name: str, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls.name = name
        (cls.response_type,) = get_args(get_original_bases(cls)[0]) or (None,)

        # Enforce dataclass behavior
        dataclass(frozen=True, kw_only=True)(cls)

    def to_dict(self) -> dict[str, str]:
        data = {"a": self.name}
        for field in dataclasses.fields(self):  # type: ignore[arg-type]
            value = getattr(self, field.name)
            api_alias = field.metadata.get("api_alias", field.name)
            data[api_alias] = value

        return data

    @classmethod
    def parse_response(cls, raw: Any) -> Response:
        rt = cls.response_type
        if not isinstance(rt, type) or not dataclasses.is_dataclass(rt):
            return raw  # type: ignore[no-any-return]

        from mega_cli.api.errors import MegaProtocolError

        if not isinstance(raw, dict):
            raise MegaProtocolError(
                f"Expected an object for {cls.name!r} ({rt.__name__}), got {raw!r:.200}"
            )

        fields = dataclasses.fields(rt)
        aliases = {f.name: f.metadata.get("api_alias", f.name) for f in fields}

        # Extra keys from the API are ignored; only required fields (no default) must be present
        missing = [
            aliases[f.name]
            for f in fields
            if f.init
            and f.default is dataclasses.MISSING
            and f.default_factory is dataclasses.MISSING
            and aliases[f.name] not in raw
        ]
        if missing:
            raise MegaProtocolError(
                f"Response for {cls.name!r} ({rt.__name__}) is missing required fields "
                f"{missing}, got {raw!r:.200}"
            )

        kwargs = {name: raw[alias] for name, alias in aliases.items() if alias in raw}
        return rt(**kwargs)  # type: ignore[return-value]
