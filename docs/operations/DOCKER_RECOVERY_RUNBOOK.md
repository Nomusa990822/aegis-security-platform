# AEGIS Docker Recovery Runbook

## 1. Purpose and scope

Use this runbook to recover the local, single-container AEGIS Docker Compose demonstration when the container or its image storage becomes unusable, while preserving the existing SQLite database and signed response-audit checkpoints.

This procedure is for the repository's current Compose deployment:

- Compose service: `aegis`
- Container name: `aegis-security-platform`
- Image tag: `aegis-security-platform:local`
- Persistent mount: named Docker volume mounted at `/data`
- Database: `/data/aegis.db`
- Checkpoints: `/data/audit_checkpoints`

The actual Compose-generated volume name is normally `<project>_aegis-data`. Discover and verify its exact name; do not assume it from the directory name.

**Primary safety rule: preserve the existing named volume.** Rebuilding an image and recreating a container are separate from deleting persistent volume data. Never use `docker compose down -v`, `docker volume rm`, or volume-pruning commands during this recovery.

This is an operational procedure for the local demonstration, not a production disaster-recovery plan. Maintain independent, tested backups for important data.

## 2. Recovery principles

1. Inspect before changing anything.
2. Preserve the original database, checkpoint files, signing key, and key ID.
3. Verify the database and checkpoint evidence before rebuilding whenever possible.
4. Confirm the exact Compose volume mapping before recreating the container.
5. Clear BuildKit cache only when diagnostics indicate damaged or missing build-cache snapshots.
6. Rebuild the image, then recreate only the AEGIS service.
7. Verify API health, container security settings, and audit integrity after recovery.
8. Record results without recording secrets.

Do not regenerate signing keys or checkpoints to make a failed verification appear successful. A replacement key cannot recreate the trust relationship of a lost key.

## 3. Read-only initial assessment

Run commands from the repository root.

### 3.1 Check repository and Compose state

```bash
git status --short --branch
git log -1 --format='%H%n%s'

docker compose ps
docker ps -a --no-trunc
docker image ls
docker system df -v
docker info --format 'StorageDriver={{.Driver}} DockerRootDir={{.DockerRootDir}}'
```

Inspect the affected container if it exists:

```bash
docker inspect aegis-security-platform
docker logs --tail 100 aegis-security-platform
```

A Docker error such as `RWLayer of container ... is unexpectedly nil`, a missing overlay snapshot, or a container that cannot be started may indicate damaged container/image storage. Do not infer that the named data volume is damaged from a container writable-layer error.

### 3.2 Identify and verify the persistent volume

Inspect the effective Compose configuration:

```bash
docker compose config --format json
```

The AEGIS service must have exactly one named volume mounted at `/data`. Resolve the actual Docker volume name and inspect it:

```bash
docker volume ls
docker volume inspect <exact-compose-volume-name>
```

Record the exact volume name and mountpoint. Confirm it is the same volume referenced by the AEGIS service. Stop if the mapping is missing, ambiguous, or different from the expected existing volume.

Do not create a replacement volume as a workaround.

### 3.3 Inspect volume contents without modifying them

On a Linux Docker host, inspect the exact mountpoint reported by `docker volume inspect`. Use read-only listing/stat commands, for example:

```bash
sudo -n find <volume-mountpoint> -maxdepth 2 -type f -printf '%M %u:%g %s %p\\n'
```

Do not change ownership or permissions as part of diagnosis. Do not copy files over the originals.

## 4. Verify database and signed checkpoint evidence before recovery

If the damaged container cannot start, use the host-side Python environment and the repository's official inventory utility. The following example assumes the volume name has been independently verified and the repository contains the private `.env` file.

The command exports the signing configuration to the current shell and passes only the required variables to the privileged inventory process. It does not print secret values.

```bash
set -a
. ./.env
set +a

export AEGIS_DATABASE_PATH="<verified-volume-mountpoint>/aegis.db"
export AEGIS_AUDIT_CHECKPOINT_DIR="<verified-volume-mountpoint>/audit_checkpoints"
export PYTHONPATH="$PWD/backend"

sudo -n --preserve-env=AEGIS_DATABASE_PATH,AEGIS_AUDIT_CHECKPOINT_DIR,AEGIS_AUDIT_CHECKPOINT_KEY,AEGIS_AUDIT_CHECKPOINT_KEY_ID,AEGIS_AUDIT_CHECKPOINT_PREVIOUS_KEYS,AEGIS_AUDIT_CHECKPOINT_LEGACY_KEY,PYTHONPATH \
  python3 -m app.response.checkpoint_inventory \
  --database "$AEGIS_DATABASE_PATH"
```

Replace both mountpoint placeholders with the exact mountpoint returned by Docker. Do not paste or commit `.env`, signing keys, analyst tokens, or approver tokens.

The inventory utility is used without an apply/recovery flag. Treat this as an inspection step. Review the output for:

- Database connection reported as read-only.
- Every expected response record and chain head present.
- `hash_chain_valid: true`.
- `lifecycle_valid: true`.
- `checkpoint_readable: true`.
- `checkpoint_signature_valid: true`.
- `checkpoint_matches_database: true`.
- No errors, orphan checkpoint files, pending checkpoint intents, quarantine evidence, temporary files, or unrecognized files unless they are understood and separately investigated.

If SQLite command-line tools are available, an additional read-only integrity check can be performed against the database:

```bash
sqlite3 -readonly "<verified-volume-mountpoint>/aegis.db" \
  'PRAGMA integrity_check; PRAGMA foreign_key_check;'
```

Expected results are `ok` for the integrity check and no rows from the foreign-key check. Do not open the database for writes or run migrations during recovery.

**Stop and investigate** if database integrity, hash-chain validation, checkpoint signature validation, or checkpoint-to-database matching fails. Preserve the original files and logs. Do not bootstrap, regenerate, quarantine, repair, or apply checkpoint recovery operations without a separately reviewed recovery plan and explicit approval.

## 5. Rebuild damaged Docker image/build storage

Only perform this section after confirming the persistent volume identity and recording the pre-recovery inventory results.

### 5.1 Confirm the base image

The repository Dockerfile currently uses `python:3.14-slim`. If Docker reports missing base-image layers or content digests, pull the configured base image:

```bash
docker pull python:3.14-slim
```

### 5.2 Clear BuildKit build cache only, when diagnostics justify it

If builds fail because BuildKit references missing or invalid cache snapshots, clear the build cache:

```bash
docker builder prune --all --force
```

This removes build cache for the selected builder. It is not a volume backup and it is not a data-recovery operation. Verify that the AEGIS named volume still exists immediately before and after cache pruning:

```bash
docker volume inspect <exact-compose-volume-name>
```

Do not substitute any of the following:

- `docker system prune`
- `docker system prune --volumes`
- `docker volume prune`
- `docker volume rm`
- `docker compose down -v`

If cache pruning does not resolve the build failure, stop and diagnose the Docker storage backend rather than repeatedly pruning or deleting data.

### 5.3 Rebuild the AEGIS image

From the repository root:

```bash
docker compose --progress plain build aegis
docker image inspect aegis-security-platform:local \
  --format 'ID={{.Id}} SIZE={{.Size}} OS={{.Os}} ARCH={{.Architecture}}'
```

Confirm the build completes and the resulting image has a plausible non-trivial size and the expected platform. Do not recreate the container until the image build succeeds.

## 6. Recreate only the AEGIS container

First verify that Compose still maps `/data` to the exact original volume. This command checks the effective configuration and stops if the mapping is not exactly the expected volume:

```bash
EXPECTED_VOLUME="<exact-compose-volume-name>"

ACTUAL_VOLUME="$(docker compose config --format json | python3 -c '
import json, sys
c = json.load(sys.stdin)
volumes = c["services"]["aegis"]["volumes"]
matches = [
    item["source"] for item in volumes
    if item.get("target") == "/data" and item.get("type") == "volume"
]
if len(matches) != 1:
    raise SystemExit("STOP: Expected exactly one named volume mounted at /data.")
print(c["volumes"][matches[0]].get("name", matches[0]))
')"

printf 'Expected: %s\\nActual:   %s\\n' "$EXPECTED_VOLUME" "$ACTUAL_VOLUME"
test "$ACTUAL_VOLUME" = "$EXPECTED_VOLUME"
```

Only after the names match, recreate the service without rebuilding the already-built image:

```bash
docker compose up -d --no-deps --force-recreate --no-build aegis
```

Inspect the resulting container:

```bash
docker inspect aegis-security-platform --format '
Status={{.State.Status}}
Image={{.Image}}
User={{.Config.User}}
ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}}
CapDrop={{json .HostConfig.CapDrop}}
SecurityOpt={{json .HostConfig.SecurityOpt}}
Mounts={{range .Mounts}}{{.Name}} -> {{.Destination}}; {{end}}
'
```

Confirm all of the following:

- Status is `running`.
- The image ID is the image that was just built.
- User is `aegis`, not root.
- `ReadonlyRootfs=true`.
- `CapDrop=["ALL"]`.
- Security options include `no-new-privileges:true`.
- The original named volume is mounted at `/data`.

Do not use `docker compose down -v` as a shortcut. The targeted `up --force-recreate` operation replaces the service container while retaining the named volume.

## 7. Post-recovery verification

### 7.1 Wait for the health endpoint

```bash
HEALTH_OK=0

for attempt in $(seq 1 15); do
    if curl --silent --show-error --fail \
        http://127.0.0.1:8000/api/v1/health; then
        echo
        HEALTH_OK=1
        break
    fi
    sleep 2
done

if [ "$HEALTH_OK" -ne 1 ]; then
    echo "FAIL: API health endpoint did not become healthy."
    docker logs --tail 100 aegis-security-platform
    exit 1
fi

docker compose ps
docker inspect aegis-security-platform \
  --format 'Status={{.State.Status}} Health={{if .State.Health}}{{.State.Health.Status}}{{else}}not-configured{{end}}'
```

The health endpoint should report a healthy application and a connected database. Docker health should become `healthy`.

### 7.2 Re-run the official checkpoint inventory inside the container

When the container is running, its configured environment supplies the checkpoint signing configuration and persistent paths. Run the read-only inventory again:

```bash
docker exec aegis-security-platform \
  python -m app.response.checkpoint_inventory \
  --database /data/aegis.db
```

Compare this result with the pre-recovery inventory. Confirm that the same response records, event counts, final hashes, chain heads, checkpoint key IDs, and verification states remain. In particular:

- `hash_chain_valid: true`
- `lifecycle_valid: true`
- `checkpoint_signature_valid: true`
- `checkpoint_matches_database: true`
- `errors: []`

Do not regard an HTTP health response alone as proof of audit integrity. Both application health and checkpoint verification are required.

### 7.3 Confirm the container remains healthy

```bash
docker inspect aegis-security-platform \
  --format 'Status={{.State.Status}} ExitCode={{.State.ExitCode}}'
```

Review application logs if any health or inventory check fails. Do not modify database or checkpoint files to silence an error.

## 8. Recovery stop conditions

Stop the procedure and preserve evidence if any of these occur:

- The expected named volume is missing or the Compose mapping changes.
- The database fails SQLite integrity checks.
- The audit hash chain, lifecycle, checkpoint signature, or checkpoint/database match is invalid.
- The checkpoint signing key or key ID is unavailable.
- The rebuilt image fails to build or cannot be inspected.
- The recreated container does not use the expected image, non-root user, security options, or original volume.
- The API does not become healthy or the database is disconnected.
- The post-recovery inventory differs unexpectedly from the pre-recovery inventory.

Do not delete the original container, image, volume, database, or checkpoint evidence as an improvised response. Escalate to a separately planned recovery procedure.

## 9. Recovery record

Record the following in the incident or engineering log:

| Field | Record |
|---|---|
| Date/time and timezone | |
| Repository commit | |
| Docker storage driver | |
| Initial Docker/container error | |
| Exact persistent volume name | |
| Pre-recovery SQLite integrity result | |
| Pre-recovery checkpoint inventory result | |
| Build-cache action and result | |
| Rebuilt image ID | |
| Recreated container image ID | |
| Post-recovery API health | |
| Post-recovery container security settings | |
| Post-recovery checkpoint inventory result | |
| Outstanding issues | |

Never include signing keys, API tokens, private `.env` contents, or other credentials in the recovery record.

## 10. Verified recovery example — 12 November 2026

The AEGIS Codespaces demonstration environment experienced a Docker container storage failure. The previous container could not start and Docker reported an `RWLayer ... is unexpectedly nil` error.

The recovery was completed with the following verified results:

- The original named volume, `aegis-security-platform_aegis-data`, was preserved.
- The pre-recovery SQLite integrity check returned `ok`; the foreign-key check returned no violations.
- The pre-recovery signed checkpoint inventory reported a valid hash chain, lifecycle, signature, and database match, with no inventory errors.
- BuildKit build cache was cleared after build failures reported missing cache/snapshot content. The named volume identity was checked before and after cache pruning.
- The AEGIS image rebuilt successfully as `sha256:7e9d0a1de7e5cfa0423299acb0e1f353fd0ab58af7373cbb943d65f6f0e5573`.
- The container was recreated using the existing named volume, with no volume deletion or database reset.
- The API returned `status: healthy` and `database: connected`; Docker reported the container healthy.
- The post-recovery inventory confirmed response record 1, event count 1, the same final hash, a valid signature under key ID `local-v1`, a matching database checkpoint, and a valid hash chain and lifecycle.
- The post-recovery inventory reported no errors, orphan checkpoint files, pending checkpoint intents, quarantine evidence, temporary files, or unrecognized files.
- The container ran as `aegis`, with a read-only root filesystem, all Linux capabilities dropped, and `no-new-privileges:true`.

This is evidence of a successful recovery of that specific local environment. It is not a claim that backups were tested, that Docker host storage was repaired generally, or that the deployment is production-ready.

---

**Document:** AEGIS Docker Recovery Runbook  
**Scope:** Local Docker Compose demonstration  
**Persistent data:** SQLite database and signed response-audit checkpoints  
**Related guidance:** [Audit Checkpoint Key Management and Rotation Runbook](../security/AUDIT_CHECKPOINT_KEY_ROTATION.md)
