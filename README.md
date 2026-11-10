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

## Entwicklung

Für Tests, Formatierung und Typprüfung gibt es folgende `make`-Befehle:

| Befehl        | Beschreibung                                                        |
|---------------|---------------------------------------------------------------------|
| `make test`   | Führt alle Tests aus                                                |
| `make lint`   | Prüft Code-Stil und Typisierung                                     |
| `make format` | Prüft die Codeformatierung (ohne Änderungen vorzunehmen)            |
| `make check`  | Führt alle Prüfungen aus (`test`, `lint`, `format`)                 |
| `make fix`    | Formatiert den Code und behebt automatisch behebbare Lint-Fehler    |

### Vor jedem Push / Pull Request

```bash
make fix     # Code automatisch formatieren und korrigieren
make check   # Sicherstellen, dass alle Prüfungen bestehen
```

Verbleibende Fehler aus `make check` müssen manuell behoben werden

### Sprache

Die Entwicklung erfolgt auf **Englisch**, damit Code und Ausgaben einheitlich zu Bibliotheken wie `typer` passen,
die bereits englische Hilfe- und Fehlertexte erzeugen. Das gilt für:

- Code (Variablen-, Funktions- und Klassennamen)
- Kommentare und Docstrings
- Commit-Messages (ggf. Branch-Namen)
- Alle Ausgaben für Nutzer (CLI-Meldungen, Hilfetexte, Fehlermeldungen)

Nur die Projektdokumentation (z. B. diese README), Issues, PRs sind auf Deutsch

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
