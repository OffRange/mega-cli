from dataclasses import asdict, dataclass


@dataclass
class BaseCommand:
    """Every command MEGA understands has this shared structure"""

    a: str

    @property
    def name(self) -> str:
        return self.a

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    def get(self, key: str, default: str) -> str:
        return asdict(self).get(key, default)

    def __getitem__(self, key) -> str:
        return asdict(self)[key]
