# IT-Softwareprojekt: MEGA CLI

Ein Kommandozeilen-Client für [MEGA](https://mega.io), der die MEGA-API direkt anspricht (eigene Implementierung von
Login, Verschlüsselung und Up-/Download, ohne das offizielle SDK).

**Python:** >= 3.13\
**Projektverwaltung:** uv\
**Quellen:** [MEGA SDK](https://github.com/meganz/sdk), [MEGA Webclient](https://github.com/meganz/webclient), [mega-rs](https://github.com/Hirevo/mega-rs), [go-mega](https://github.com/t3rm1n4l/go-mega)\
**Codeguidelines:** Funktionen, Variablen, Kommentare, sowie Textausgabe in Englisch

---

## Geplante Ordnerstruktur

```
mega-cli/
├── pyproject.toml
├── uv.lock
├── .python-version
├── .gitignore
├── README.md
├── Makefile                   # shortcuts for CI
├── src/
│   └── mega_cli/
│       ├── __init__.py
│       ├── __main__.py        # enables `python -m mega_cli`
│       ├── config.py          # paths (platformdirs), API URL, timeouts
│       ├── session.py         # save/load session: secrets in OS keyring, 0600 file fallback
│       ├── auth.py            # functions to establish a session
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── app.py         # Typer app, registers commands
│       │   ├── auth.py        # login, logout, whoami
│       │   ├── files.py       # ls, mkdir, mv, rm, rename, quota
│       │   ├── transfer.py    # get, put, link
│       │   └── output.py      # Rich console, tables, progress bars
│       ├── api/
│       │   ├── __init__.py
│       │   ├── client.py      # POST /cs, request-id counter, sid, retry/backoff on -3 (EAGAIN)
│       │   ├── commands.py    # definitions of API commands (us, us0, ug, f, p, m, d, a, g, u, l, ...)
│       │   ├── errors.py      # error-code enum and MegaError exception
│       │   └── hashcash.py    # proof-of-work solver for HTTP 402 / X-Hashcash
│       ├── crypto/
│       │   ├── __init__.py
│       │   ├── encoding.py    # base64url
│       │   ├── keys.py        # PBKDF2-HMAC-SHA512 (v2), AES-ECB key wrapping
│       │   ├── rsa.py         # MPI parsing, csid -> sid (raw RSA via pow(), see notes)
│       │   ├── attributes.py  # encrypt/decrypt "MEGA{...}" attribute blobs
│       │   └── filecrypto.py  # file key split, AES-CTR, chunk MAC, meta-MAC
│       ├── fs/
│       │   ├── __init__.py
│       │   ├── node.py        # Node dataclass (handle, parent, type, name, size, key)
│       │   └── tree.py        # build tree from `f` response, resolve "/a/b/c.txt" to node
│       └── transfer/
│           ├── __init__.py
│           ├── chunks.py      # chunk boundaries (128 KiB, 256 KiB, ... up to 1 MiB, then 1 MiB each)
│           ├── download.py
│           └── upload.py
└── tests/
    ├── conftest.py
    ├── crypto/
    │   ├── test_encoding.py
    │   ├── test_keys.py
    │   ├── test_rsa.py
    │   ├── test_attributes.py
    │   └── test_filecrypto.py
    ├── api/
    │   ├── test_client.py     # mocked HTTP: retries, error codes, 402 handling
    │   └── test_hashcash.py
    ├── fs/
    │   └── test_tree.py       # path resolution, edge cases (trash, duplicate names)
    └── transfer/
        └── test_chunks.py
```

## Abhängigkeiten

### Produktion

| Paket          | Zweck                                                       |
|----------------|-------------------------------------------------------------|
| `typer`        | CLI-Framework (Befehle, Optionen, Hilfetexte)               |
| `httpx2`       | HTTP-Requests an die MEGA-API (gepflegter Fork von `httpx`) |
| `cryptography` | AES (ECB, CBC, CTR) für die Ende-zu-Ende-Verschlüsselung    |
| `rich`         | Formatierte Terminal-Ausgaben, Tabellen, Fortschrittsbalken |
| `platformdirs` | Plattformspezifische Pfade für Session- und Konfigdateien   |
| `keyring`      | Session-Secrets im OS-Keyring speichern                     |

Aus der Standardbibliothek (keine zusätzliche Abhängigkeit):
`hashlib` (PBKDF2, SHA), `secrets` (Zufallsschlüssel), `base64`, `struct`, `json`, `pow()` für Raw-RSA.

### Entwicklung

| Paket        | Zweck                                 |
|--------------|---------------------------------------|
| `pytest`     | Tests                                 |
| `pytest-cov` | Testabdeckung messen                  |
| `ruff`       | Linting und einheitliche Formatierung |
| `mypy`       | Statische Typprüfung                  |

HTTP-Mocking: `httpx2.MockTransport` oder `pytest-httpx2`.

## CLI

Einige beispiel CLI-Befehle, die unser Projekt unterstützen sollte:

```
mega-cli login [<email>]
mega-cli logout

mega-cli whoami
mega-cli ls
mega-cli get <remote> [<local>]
mega-cli put <local> <remote> [--force]
mega-cli mkdir <remote>
mega-cli mv <src> <dest>
mega-cli rm [-r] <file>
mega-cli share <file> [--remove]
```

## Technische Hinweise

- **RSA:** `cryptography` bietet keine RSA-Entschlüsselung ohne Padding an, MEGA verwendet aber
  Raw-RSA für `csid`. Lösung: Schlüssel aus den MPIs parsen und mit `pow(c, d, n)` entschlüsseln.
- **PBKDF2:** `hashlib.pbkdf2_hmac("sha512", ...)` aus der Standardbibliothek reicht aus.
- **Meta-MAC:** Die Chunk-MACs sind AES-CBC-MACs; dafür AES-CBC mit Null-IV aus `cryptography` nutzen.
- **Session-Sicherheit:** Der Master-Key gibt Zugriff auf alle Dateien. sid und Master-Key liegen deshalb im
  OS-Keyring (Windows Credential Manager, macOS Keychain, Linux Secret Service). Ohne Keyring (z. B. per SSH) Fallback
  auf eine 0600-Datei mit Warnung.
- **Retries:** Fehlercode `-3` (EAGAIN) mit exponentiellem Backoff wiederholen, andere
  negative Codes sofort als `MegaError` werfen.