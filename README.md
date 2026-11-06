# MEGA CLI

Eine CLI-Anwendung im Rahmen des Softwareprojekt-Moduls an der Hochschule Mittweida.

`mega-cli` ist ein Kommandozeilen-Client für [MEGA](https://mega.io). Die MEGA-API wird direkt angtesprochen,
Login, Ende-zu-Ende-Verschlüsselung sowie Up- und Download sind nach Aufgabenstellung selbst zu implementieren, ohne das
offizielle SDK.

## Voraussetzungen

- Python >= 3.13
- [uv](https://docs.astral.sh/uv/) (empfohlen) **oder** pip >= 25.1

## Installation

```bash
git clone <repo-url>
cd mega-cli
```

### Mit uv (empfohlen)

```bash
uv sync --all-groups
```

`uv sync` legt die virtuelle Umgebung in `.venv/` an und installiert alle Abhängigkeiten, inklusive der
Entwicklungswerkzeuge, exakt in den Versionen aus `uv.lock`.

### Mit pip

```bash
python3.13 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -U pip
pip install -e . --group dev
```

`--group dev` installiert die Entwicklungswerkzeuge und benötigt pip >= 25.1. Hinweis: pip ignoriert
`uv.lock`, die Versionen können daher von denen mit uv abweichen.

## Verwendung

```bash
uv run mega-cli          # mit uv
mega-cli                 # in der aktivierten venv
python -m mega_cli       # alternativ
```

### Geplante Befehle & Struktur

siehe [STRUCTURE.md](STRUCTURE.md)

## Quellen

- [MEGA SDK](https://github.com/meganz/sdk)
- [MEGA Webclient](https://github.com/meganz/webclient)
- [mega-rs](https://github.com/Hirevo/mega-rs)
- [go-mega](https://github.com/t3rm1n4l/go-mega)
