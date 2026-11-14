#!/bin/sh
# Online, consistent snapshot of the crabby_proxy SQLite database.
#
# Uses SQLite's online backup API (`.backup`), which is safe while the proxy is
# running in WAL mode: it copies a transactionally consistent image without
# stopping writers. Each snapshot is integrity-checked and gzipped, and
# snapshots older than the retention window are pruned.
#
# Usage:
#   backup-sqlite.sh [DB_PATH] [BACKUP_DIR]
#
# Environment (all optional; positional arguments win):
#   DB_PATH          source database        (default /app/data/proxy.db)
#   BACKUP_DIR       destination directory  (default /backups)
#   RETENTION_DAYS   delete snapshots older than this many days
#                    (default 14; 0 keeps everything)
#   INTERVAL_SECONDS if set, loop forever and take a snapshot every N seconds
#                    (the compose `backup` sidecar does this); unset runs once
#                    (use that form from host cron)
#
# Requires the sqlite3 CLI and gzip. Copy BACKUP_DIR off-host (rclone, restic,
# rsync, object storage, ...): a backup on the same disk as the volume does not
# survive losing that disk.
set -eu

DB_PATH="${1:-${DB_PATH:-/app/data/proxy.db}}"
BACKUP_DIR="${2:-${BACKUP_DIR:-/backups}}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-}"

log() { printf '%s backup-sqlite: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

snapshot() {
    if [ ! -f "$DB_PATH" ]; then
        log "source $DB_PATH does not exist yet; skipping"
        return 0
    fi
    mkdir -p "$BACKUP_DIR"
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    tmp="$BACKUP_DIR/.proxy-$stamp.db.partial"
    out="$BACKUP_DIR/proxy-$stamp.db.gz"

    # .timeout waits out a briefly locked database instead of failing.
    if ! sqlite3 "$DB_PATH" ".timeout 10000" ".backup '$tmp'"; then
        log "backup of $DB_PATH failed"
        rm -f "$tmp"
        return 1
    fi

    # The copy inherits WAL mode; switch it to a self-contained rollback-journal
    # file (the proxy re-enables WAL when it opens a restored DB), then verify.
    result=$(sqlite3 "$tmp" "PRAGMA journal_mode=DELETE;" "PRAGMA integrity_check;" | tail -n 1)
    if [ "$result" != "ok" ]; then
        log "integrity_check FAILED for $tmp: $result"
        rm -f "$tmp" "$tmp-wal" "$tmp-shm"
        return 1
    fi

    gzip -c "$tmp" >"$out.partial"
    mv "$out.partial" "$out"
    rm -f "$tmp" "$tmp-wal" "$tmp-shm"
    log "wrote $out ($(wc -c <"$out" | tr -d ' ') bytes)"

    if [ "$RETENTION_DAYS" -gt 0 ]; then
        find "$BACKUP_DIR" -maxdepth 1 -type f -name 'proxy-*.db.gz' \
            -mtime "+$RETENTION_DAYS" -print | while read -r f; do
            rm -f "$f" && log "pruned $f"
        done
    fi
}

if [ -n "$INTERVAL_SECONDS" ]; then
    log "snapshotting $DB_PATH to $BACKUP_DIR every ${INTERVAL_SECONDS}s (retention ${RETENTION_DAYS}d)"
    while :; do
        snapshot || log "snapshot failed; retrying next interval"
        sleep "$INTERVAL_SECONDS"
    done
else
    snapshot
fi
