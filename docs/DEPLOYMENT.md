# Deployment

PhishTrace is a single-process web application with a SQLite database and a
data directory for evidence bodies, archived snapshots and generated reports.
Deploy it on a host you control, bind it to loopback, and publish it through a
TLS reverse proxy. The application refuses to bind a non-loopback address
unless authentication is enabled and `PHISHTRACE_SESSION_SECRET` is at least 32
characters, so a misconfigured public bind fails closed.

Two supported layouts:

* **Bare metal / VM with systemd** — recommended for long-lived investigations.
* **Docker Compose** — recommended for an isolated, reproducible install; the
  published port is loopback-only by default.

## 1. Prerequisites

* Linux with Python 3.11+ (3.12 recommended), `python3-venv`, `pip`.
* A dedicated unprivileged account (`phishtrace`) and a data directory
  (`/var/lib/phishtrace`).
* Optional: nginx (or another TLS terminator) and a certificate.
* Outbound HTTPS/DNS from the host if you enable active fetching or keyed
  providers. No inbound ports are needed beyond the proxy.

The eight Phase C tools (`dnstwist`, `theHarvester`, `sherlock`, `maigret`,
`holehe`, `ghunt`, `phoneinfoga`, `spiderfoot`) are optional. Install only the
ones you need; providers whose binary or credential is absent are reported as
skipped rather than failing an investigation.

### SpiderFoot

SpiderFoot is not published on PyPI, so it is deployed from a source checkout.
The runner starts `options.path` directly and cannot launch a `.cmd`/`.bat`
shim, so point `path` at a real executable - on Windows the easiest route is a
throwaway venv plus a one-line console-script wrapper that `chdir`s into the
checkout and executes `sf.py`.

Pin `netaddr<1`: 1.x dropped `IPAddress.is_private()`, which `sflib` calls
during target validation. Keep `sfp_crt` out of `options.modules`; that module
waits indefinitely on crt.sh and will burn the whole provider timeout.

## 2. Install from source

```bash
sudo useradd --system --home /opt/phishtrace --shell /usr/sbin/nologin phishtrace
sudo install -d -o phishtrace -g phishtrace -m 0750 /opt/phishtrace
sudo install -d -o phishtrace -g phishtrace -m 0700 /var/lib/phishtrace
sudo -u phishtrace git clone https://github.com/<your-org>/phishtrace.git /opt/phishtrace
cd /opt/phishtrace
sudo -u phishtrace python3 -m venv .venv
sudo -u phishtrace .venv/bin/pip install --upgrade pip
sudo -u phishtrace .venv/bin/pip install .
```

`config.yaml` and the `config/stoplists/` files must be readable by the service
account; the package install does not copy them outside the checkout.

## 3. Configure

Edit `config.yaml` (non-secret settings) and create `.env` (secrets):

```bash
sudo -u phishtrace cp .env.example .env
sudo -u phishtrace chmod 600 .env
```

Set at minimum:

```dotenv
PHISHTRACE_SESSION_SECRET=<48+ random characters>
```

Generate one with
`python3 -c "import secrets; print(secrets.token_urlsafe(48))"`.
Add only the provider keys you actually have; the rest stay skipped.

Create the first administrator (interactive, or non-interactive with
`PHISHTRACE_ADMIN_PASSWORD`):

The service stores data in `/var/lib/phishtrace`, so point the one-off command
at the same directory (otherwise the account is created in the checkout and the
service starts with an empty database):

```bash
sudo -u phishtrace env PHISHTRACE_DATA_DIR=/var/lib/phishtrace \
    /opt/phishtrace/.venv/bin/phishtrace create-admin --username analyst
# or non-interactive:
sudo -u phishtrace env PHISHTRACE_DATA_DIR=/var/lib/phishtrace \
    PHISHTRACE_ADMIN_PASSWORD='...' \
    /opt/phishtrace/.venv/bin/phishtrace create-admin --username analyst
```

Check the effective configuration and provider availability before starting:

```bash
sudo -u phishtrace .venv/bin/phishtrace doctor
sudo -u phishtrace .venv/bin/phishtrace providers
```

`doctor --validate` makes harmless live key-validation calls; omit the flag if
you do not want any outbound request.

## 4. systemd

```bash
sudo install -d -o root -g phishtrace -m 0750 /etc/phishtrace
sudo install -o root -g phishtrace -m 0640 deploy/phishtrace.env.example /etc/phishtrace/phishtrace.env
sudo editor /etc/phishtrace/phishtrace.env
sudo install -m 0644 deploy/phishtrace.service /etc/systemd/system/phishtrace.service
sudo systemctl daemon-reload
sudo systemctl enable --now phishtrace
sudo systemctl status phishtrace --no-pager
sudo journalctl -u phishtrace -f
```

The unit runs as `phishtrace`, keeps the system tree read-only, grants write
access only to `/var/lib/phishtrace` (`StateDirectory`), drops all capabilities,
and applies seccomp and namespace restrictions. It reads
`PHISHTRACE_DATA_DIR=/var/lib/phishtrace` from the environment file.

Health check from the host:

```bash
curl -fsS http://127.0.0.1:8088/health | jq .
```

## 5. TLS reverse proxy

Terminate TLS at nginx and proxy to the loopback listener. The UI uses
Server-Sent Events for live progress, so buffering must be disabled and the read
timeout raised.

```nginx
server {
    listen 443 ssl http2;
    server_name phishtrace.example.org;

    ssl_certificate     /etc/letsencrypt/live/phishtrace.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/phishtrace.example.org/privkey.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    client_max_body_size 8m;

    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
    }
}
```

Set `auth.cookie_secure: true` in `config.yaml` when the console is served over
TLS (this also emits HSTS). The application honors `X-Forwarded-For` only when
the immediate peer is listed in `PHISHTRACE_TRUSTED_PROXIES` (default
`127.0.0.1,::1`), so login throttling and audit entries record the real client
without letting a direct client spoof the header. If the proxy connects from a
container gateway address, add that address to the variable.

Do not expose port 8088 publicly. If you must bind a public interface directly,
set `auth.enabled: true`, `PHISHTRACE_SESSION_SECRET`, `cookie_secure: true`
and a firewall allowlist.

## 6. Docker

```bash
cp .env.example .env
# set PHISHTRACE_SESSION_SECRET and any provider keys
docker compose build
docker compose up -d
docker compose exec phishtrace phishtrace create-admin --username analyst
docker compose ps
```

Compose publishes `127.0.0.1:8088`, drops all capabilities, sets
`no-new-privileges`, runs the container with a read-only root filesystem and
keeps state in the `phishtrace-data` volume. The container binds `0.0.0.0`
internally because `PHISHTRACE_HOST` is set in `docker-compose.yml`; the host
port remains loopback-only. Put nginx in front as above, and set
`PHISHTRACE_TRUSTED_PROXIES` to the address the proxy uses to reach the
published port (often `172.17.0.1`, not `127.0.0.1`).

The image healthcheck calls `/health` every 30 seconds. Application data lives
in the named volume; `docker compose down` keeps it, `down -v` destroys it.

## 7. Backups and restore

Back up the SQLite database together with the evidence/archive/report tree.

```bash
sudo systemctl stop phishtrace
sudo sqlite3 /var/lib/phishtrace/phishtrace.db ".backup '/backup/phishtrace-$(date +%F).db'"
sudo tar -C /var/lib -czf /backup/phishtrace-data-$(date +%F).tar.gz phishtrace
sudo systemctl start phishtrace
```

Restoring is the reverse: stop the service, restore the database and data
directory with the same ownership (`phishtrace:phishtrace`, mode 0700), start
the service, and check `/health`. Evidence rows reference files by path; a
database restored without the evidence tree will show purged bodies.

For Docker, stop the stack and archive the volume, or run `sqlite3` inside the
container against `/data/phishtrace.db`.

## 8. Retention and upgrades

`retention_days` (default 180) drives `phishtrace purge`, which deletes old
investigations and their now-orphaned evidence files. Schedule it if you need
automatic retention; it is not run by the web process.

To upgrade:

```bash
sudo systemctl stop phishtrace
sudo -u phishtrace git -C /opt/phishtrace pull --ff-only
sudo -u phishtrace /opt/phishtrace/.venv/bin/pip install .
sudo systemctl start phishtrace
```

The schema is created at startup with SQLAlchemy ``create_all``. There is no
automatic migration framework yet: an upgrade that changes existing tables
needs a manual migration or a fresh database. Take a backup first; downgrades
are not supported.

## 9. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Refusing to bind '0.0.0.0'` | Auth or a 32+ character `PHISHTRACE_SESSION_SECRET` is missing. |
| Login page loops or sessions drop on restart | No persistent session secret; set `PHISHTRACE_SESSION_SECRET`. |
| Live progress stalls behind nginx | `proxy_buffering` is on; disable it for the location. |
| All clients show as `127.0.0.1` | Proxy address is not in `PHISHTRACE_TRUSTED_PROXIES`. |
| A provider is skipped | Its key/binary is missing; run `phishtrace providers` or `doctor`. |
| Evidence says "purged" | The file was removed while the database row remained; restore the data directory. |
| PDF report fails | ReportLab/font issue; reinstall with `pip install --force-reinstall reportlab`. |

Logs go to the journal (systemd) or `docker logs`. Investigation errors are
stored on the investigation row and shown in the UI; provider payloads are
never written to the log.

## 10. Linux VPS deployment

This is the concrete layout of the Linux instance that runs alongside the
Windows host. Both serve the same application version; the Windows box keeps
its own database so the two can be compared side by side.

| Item | Path |
| --- | --- |
| Code and virtualenv | `/opt/phishtrace`, `/opt/phishtrace/.venv` |
| Service account | `phishtrace` (no shell, no home data) |
| Database and captures | `/var/lib/phishtrace/phishtrace.db`, `/var/lib/phishtrace/evidence/` (mode `0700`) |
| Secrets | `/etc/phishtrace/phishtrace.env` (`0640 root:phishtrace`) |
| systemd unit | `/etc/systemd/system/phishtrace.service` |
| Bind address | `127.0.0.1:8098` (nginx terminates TLS) |
| nginx vhost | `/etc/nginx/sites-available/phishtrace.conf`, listening on `8443` |
| TLS material | `/etc/nginx/tls/` (self-signed, `CN=167.233.192.198`) |
| theHarvester | `/opt/phishtrace/.tools/theharvester-venv/bin/theHarvester`, referenced from `config.yaml` |

The host already runs `exrmm-portal.service` and the
`mysystemservices.exrmm.com` site, whose catch-all `default_server` answers
unmatched traffic with `444` and rejects unknown TLS handshakes. The
PhishTrace vhost therefore uses its own port (`8443`) instead of a new
`server_name`, which keeps the existing site and its Let's Encrypt
certificate untouched. A trusted certificate needs a DNS record for a
dedicated name first; once that exists, point certbot at the vhost and drop
`ssl_reject_handshake` from the catch-all for that name only.

The venv install is editable (`pip install -e /opt/phishtrace`), so a code
change is deployed by copying the file and restarting the unit:

```bash
scp phishtrace/api/routes.py root@host:/opt/phishtrace/phishtrace/api/routes.py
ssh root@host 'systemctl restart phishtrace && curl -sS http://127.0.0.1:8098/health'
```

### Migrating data from another instance

1. Snapshot the source database with the sqlite3 backup API (never copy a
   live WAL database with plain `cp`).
2. Archive the `evidence/` tree and copy both to the target host.
3. Rewrite every `evidence.raw_response_path` row to the target's evidence
   root, then confirm the row count and that no path is missing.
4. `chown -R phishtrace:phishtrace /var/lib/phishtrace`, `chmod 700`, restart.

The last migration moved 23 investigations and 2,180 capture rows with zero
missing files. Orphaned rows are the failure mode to watch for: the purge
command deletes files it knows about but leaves rows whose file vanished,
so always check the `missing` count before trusting the copy.

### Evidence preview budget

Captures are previewed from local disk, so the budget is about browser work,
not bandwidth. HTML keeps a larger budget (2 MB) than opaque bodies (100 KB)
because a real page spends its first hundred kilobytes on inline CSS;
truncating there leaves the sandboxed frame empty, which looks like the
renderer failed. Above the budget the API sets `preview_truncated` and the
console shows a "preview limited to" chip instead of quietly showing a
partial page.
