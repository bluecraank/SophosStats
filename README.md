# SophosStats

Sammelt Statistiken von Sophos-XGS-Firewalls (SFOS) und stellt sie in einer Weboberfläche mit Login dar.

| Bereich | Quelle | Intervall |
|---|---|---|
| CPU, RAM, Disk, Swap, Uptime, Live-User, Modell/Firmware | SNMP v3 (SFOS-MIB, HOST-RESOURCES-MIB) | Standard 60 s |
| Interface-Durchsatz und -Status | SNMP v3 (IF-MIB, 64-Bit-Zähler) | Standard 60 s |
| Firewall-/NAT-Regeln, Gruppen, Interfaces, Zonen, Hosts, Dienste, VPN, Routen | XML-API | Standard 15 min |
| Konfigurationsänderungen (hinzugefügt/geändert/entfernt) | Vergleich der XML-API-Abrufe | mit jedem Abruf |
| Logs (alle Kategorien), Volltextsuche | Syslog UDP/TCP 5514 | laufend |
| **Regelnutzung**: Treffer, Blockierungen, Bytes/Pakete gesendet/empfangen, zuletzt genutzt, Top-Quellen/-Ziele/-Ports | aus den Firewall-Logs aggregiert (stündlich) | laufend |

> Die SFOS-XML-API liefert nur Konfiguration, keine Zähler. Deshalb kommen Live-Werte per SNMP
> und Regelnutzung aus den Logs. Für eine Regel wird Nutzung nur erfasst, wenn dort
> **„Log firewall traffic“** aktiv ist. Die Werte beginnen mit dem ersten empfangenen Log.

## Architektur

```
            ┌───────────── Docker Compose ─────────────────────────────┐
Browser ──► │ web (nginx, TLS) ──► api (FastAPI) ──┐                    │
            │                                       ├──► db (PostgreSQL │
XGS ──SNMP/XML-API◄── collector (Scheduler) ────────┤     + TimescaleDB)│
XGS ──Syslog 5514──►  collector (Syslog-Empfang) ───┘                    │
            └──────────────────────────────────────────────────────────┘
```

- **Backend**: Python 3.13, FastAPI, SQLAlchemy 2.1 (async), Pydantic v2, pysnmp 7, httpx
- **Frontend**: React 19, TypeScript, Vite, TanStack Query, Recharts, Tailwind CSS 4
- **Datenbank**: TimescaleDB-Hypertables mit automatischer Aufbewahrung und Kompression
- **Collector** läuft als eigener Prozess: Er fragt jede Firewall in ihrem eigenen Intervall ab, wiederholt Fehler erst nach Ablauf des Intervalls und reagiert auf „Jetzt abrufen“.

## Sicherheit

- Lokale Benutzer mit **Argon2id**-Passwörtern und optionaler **TOTP-2FA**
- Rollen **Administrator** (Verwaltung) und **Betrachter** (nur lesen)
- Serverseitige Sessions; das Cookie ist `HttpOnly`, `Secure` und `SameSite=Strict`, gespeichert wird nur der SHA-256-Hash des Tokens
- CSRF-Schutz über einen Pflicht-Header bei allen schreibenden Requests
- Kontosperre nach 5 Fehlversuchen für 15 Minuten
- Firewall-Zugangsdaten und TOTP-Secrets werden mit **Fernet** (AES) verschlüsselt gespeichert
- XML-Antworten werden mit `defusedxml` geparst (Schutz vor XXE)
- Syslog von unbekannten Absendern wird verworfen
- nginx: nur TLS 1.2/1.3, HSTS, CSP und weitere Security-Header

## Installation

Voraussetzungen: ein Linux-Server oder eine VM mit Docker und Docker Compose.

```bash
cp .env.example .env
# ENCRYPTION_KEY erzeugen und in .env eintragen:
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
#   (alternativ: docker run --rm python:3.13-slim sh -c "pip -q install cryptography && python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'")
# Außerdem POSTGRES_PASSWORD und INITIAL_ADMIN_PASSWORD (mind. 12 Zeichen) setzen

docker compose up -d --build
```

Danach `https://<server>` öffnen und mit dem Admin aus der `.env` anmelden. Danach solltest du unter **Konto** direkt 2FA einrichten.

Ohne eigenes Zertifikat erzeugt der Web-Container ein selbstsigniertes. Für ein eigenes Zertifikat legst du `certs/tls.crt` und `certs/tls.key` ab und startest neu.

**Ports:** 443/80 (Web), 5514 UDP und TCP (Syslog von den Firewalls).

## Einrichtung auf der Sophos XGS

1. **XML-API**: *Backup & firmware → API* aktivieren und die IP des SophosStats-Servers als *Allowed IP address* eintragen. Am besten einen eigenen Admin-Benutzer mit Leserechten anlegen.
2. **SNMP v3**: *Administration → SNMP* den Agent aktivieren und einen SNMPv3-Benutzer anlegen (Auth SHA256, Verschlüsselung AES). Unter *Administration → Device access* SNMP für die Zone erlauben, in der der Server steht.
3. **Syslog**: *System services → Log settings* einen Syslog-Server hinzufügen: Server-IP, Port 5514, UDP oder TCP, Format *Device standard format*. Mindestens die Kategorie *Firewall* aktivieren, sinnvoll sind zusätzlich IPS, Web, VPN, Authentication und Admin.
4. **Regeln**: in allen Regeln, deren Nutzung du sehen willst, *Log firewall traffic* einschalten.
5. In SophosStats unter **Firewalls verwalten** die Firewall anlegen und **Verbindung testen** klicken.

Logs werden einer Firewall über die Absender-IP zugeordnet. Das ist standardmäßig der Host, abweichend das Feld „Absender-IP der Logs“. Falls Docker die Quell-IP verschleiert (etwa bei rootless Docker), setzt du den Collector auf `network_mode: host`.

## Entwicklung

```bash
# Backend
cd backend
python -m venv .venv && .venv/Scripts/activate      # Linux: source .venv/bin/activate
pip install -e . pytest pytest-asyncio ruff
# Eine PostgreSQL/TimescaleDB-Instanz bereitstellen, z.B.:
docker run -d -p 5432:5432 -e POSTGRES_USER=sophosstats -e POSTGRES_PASSWORD=sophosstats timescale/timescaledb:latest-pg17
# .env im backend-Ordner: ENCRYPTION_KEY=..., INITIAL_ADMIN_PASSWORD=..., COOKIE_SECURE=false
uvicorn app.main:app --reload          # API auf :8000, Doku unter /api/docs
python -m app.collector                # Collector
pytest && ruff check app tests

# Frontend
cd frontend
npm install
npm run dev                            # http://localhost:5173, /api wird an :8000 weitergeleitet
```

## Bekannte Grenzen / gegen eine echte Firewall zu prüfen

- **Log-Felder**: Der Parser erwartet das SFOS-Format „Device standard format“ (`key="value"`) mit den Feldern `fw_rule_id`, `fw_rule_name`, `sent_bytes`/`recv_bytes`, `sent_pkts`/`recv_pkts` und optional `con_event`. Gibt es `con_event`, zählt jede Verbindung beim Start als Treffer, und die Bytes werden beim Ende gezählt. Ohne `con_event` zählt jeder Logeintrag. Diese Logik steht in [backend/app/collectors/sfos_log.py](backend/app/collectors/sfos_log.py) und muss gegen echte Logs deiner Firmware geprüft werden.
- **Regelzuordnung**: Logs werden über den **Regelnamen** (`fw_rule_name`) mit den per XML-API abgerufenen Regeln verknüpft. Fehlt der Name im Log, landet die Nutzung unter „Nutzung ohne Regelzuordnung“ und ist nach Regel-ID aufgeführt.
- **CPU**: Die Auslastung kommt aus `hrProcessorLoad` (HOST-RESOURCES-MIB), ersatzweise aus UCD `ssCpuIdle`. Die OIDs stehen zentral in [backend/app/collectors/snmp.py](backend/app/collectors/snmp.py).
- **Schema**: Tabellen werden beim Start angelegt (`create_all`). Für spätere Schemaänderungen sollte Alembic eingeführt werden.
