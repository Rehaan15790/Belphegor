#!/usr/bin/env bash
# =============================================================================
# Belphegor admin password reset script
#
# The login username is fixed to Belphegor. The password is stored as a bcrypt hash under the
# auth.password_hash key in the database settings table. This script connects to the database, generates the bcrypt hash inside the DB with pgcrypto,
# and writes it back to that key. It is fully compatible with the backend login check (golang.org/x/crypto/bcrypt).
#
# Two deployment modes:
#   local (default) -- connects to the database directly from the host with psql. Connection info is taken in this order of precedence:
#                    command-line args > --dsn/$BELPHEGOR_PG_DSN > database.* in config.json
#   docker        -- runs psql inside the postgres container via `docker compose exec` (or `docker exec`)
#                    (compose does not expose 5432 to the host by default, so it runs inside the container).
#
# Examples:
#   ./reset-password.sh                          # local; reads config.json/environment automatically and prompts for the new password
#   ./reset-password.sh -p 'NewPass!'            # local; sets the new password directly
#   ./reset-password.sh --dsn postgres://u:p@h:5432/belphegor
#   ./reset-password.sh -H 127.0.0.1 -P 5433 -U autopentest -W pass -d belphegor
#   ./reset-password.sh -m docker                # docker deployment (reads POSTGRES_* from .env)
#   ./reset-password.sh -m docker -c pg-container-name --exec docker
#
# Security: the new password is passed via an environment variable + psql \getenv (it never appears in process argv), and is
# escaped automatically by :'var' (prevents SQL injection). The database password is passed via PGPASSWORD and likewise stays out of argv.
# =============================================================================
set -euo pipefail

PASS_KEY="auth.password_hash"
BCRYPT_COST=10

MODE=""            # local | docker (auto-detected if empty)
DSN=""
HOST="" PORT="" USER="" DBPASS="" DBNAME="" SSLMODE=""
CONFIG=""
CONTAINER=""       # postgres service/container name for docker mode (default postgres)
EXEC_KIND=""       # compose | docker (which exec to use in docker mode; auto if empty)
NEWPASS=""
ASSUME_YES=0

die() { echo "Error: $*" >&2; exit 1; }
info() { echo "· $*" >&2; }

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

# ---- argument parsing -------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode)        MODE="${2:-}"; shift 2 ;;
    --dsn)            DSN="${2:-}"; shift 2 ;;
    -H|--host)        HOST="${2:-}"; shift 2 ;;
    -P|--port)        PORT="${2:-}"; shift 2 ;;
    -U|--user)        USER="${2:-}"; shift 2 ;;
    -W|--db-password) DBPASS="${2:-}"; shift 2 ;;
    -d|--dbname)      DBNAME="${2:-}"; shift 2 ;;
    --sslmode)        SSLMODE="${2:-}"; shift 2 ;;
    --config)         CONFIG="${2:-}"; shift 2 ;;
    -c|--container)   CONTAINER="${2:-}"; shift 2 ;;
    --exec)           EXEC_KIND="${2:-}"; shift 2 ;;
    -p|--new-password) NEWPASS="${2:-}"; shift 2 ;;
    -y|--yes)         ASSUME_YES=1; shift ;;
    -h|--help)        usage ;;
    *) die "Unknown argument: $1 (use -h for usage)" ;;
  esac
done

# ---- read database.* from config.json (only in local mode and when no connection info was given) -----
# Parsing with python3 is preferred (more robust). Without python3, fall back to grep (config.json has neatly separated fields).
read_config_json() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$path" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1])).get("database", {})
except Exception:
    sys.exit(1)
# a dsn can be given directly, or the fields can be given separately
if d.get("dsn"):
    print("DSN\t" + d["dsn"]); sys.exit(0)
for k in ("host","port","user","password","dbname","sslmode"):
    if d.get(k) is not None:
        print(k.upper() + "\t" + str(d[k]))
PY
  else
    # very simple fallback: grep per key (the value is a string or number)
    local k
    for k in host port user password dbname sslmode; do
      local v
      v=$(grep -oE "\"$k\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[0-9]+)" "$path" 2>/dev/null \
            | head -1 | sed -E "s/.*:[[:space:]]*//; s/^\"//; s/\"$//") || true
      [[ -n "$v" ]] && echo -e "${k^^}\t$v"
    done
  fi
}

apply_config_fields() {
  local line key val
  while IFS=$'\t' read -r key val; do
    [[ -z "$key" ]] && continue
    case "$key" in
      DSN)      [[ -z "$DSN" ]] && DSN="$val" ;;
      HOST)     [[ -z "$HOST" ]] && HOST="$val" ;;
      PORT)     [[ -z "$PORT" ]] && PORT="$val" ;;
      USER)     [[ -z "$USER" ]] && USER="$val" ;;
      PASSWORD) [[ -z "$DBPASS" ]] && DBPASS="$val" ;;
      DBNAME)   [[ -z "$DBNAME" ]] && DBNAME="$val" ;;
      SSLMODE)  [[ -z "$SSLMODE" ]] && SSLMODE="$val" ;;
    esac
  done
}

# ---- auto-detect mode ---------------------------------------------------------
if [[ -z "$MODE" ]]; then
  if [[ -n "$DSN$HOST$USER$DBNAME" || -n "${BELPHEGOR_PG_DSN:-}" || -f "${CONFIG:-config.json}" ]]; then
    MODE="local"
  elif command -v docker >/dev/null 2>&1 && [[ -f docker-compose.yml ]]; then
    MODE="docker"
  else
    MODE="local"
  fi
fi
info "Deployment mode: $MODE"

# ---- collect the new password -----------------------------------------------------------
if [[ -z "$NEWPASS" ]]; then
  read -r -s -p "Enter new password (username is fixed to Belphegor): " NEWPASS; echo >&2
  [[ -n "$NEWPASS" ]] || die "Password must not be empty"
  read -r -s -p "Enter again to confirm: " NEWPASS2; echo >&2
  [[ "$NEWPASS" == "$NEWPASS2" ]] || die "The two entries do not match"
fi
[[ -n "$NEWPASS" ]] || die "Password must not be empty"

# pass the password to psql through an environment variable (read with \getenv; it never appears in argv/ps)
export BELPHEGOR_RESET_NEWPASS="$NEWPASS"

# generate bcrypt inside the DB and upsert it. The password is escaped automatically by :'newpw'. CREATE EXTENSION is idempotent,
# and it errors here if the database role cannot create extensions (see the failure branch of run below for guidance).
SQL=$(cat <<SQL
\\set ON_ERROR_STOP on
\\getenv newpw BELPHEGOR_RESET_NEWPASS
CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO settings(key, value)
VALUES ('$PASS_KEY', crypt(:'newpw', gen_salt('bf', $BCRYPT_COST)))
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();
SQL
)

# ---- run -----------------------------------------------------------------
if [[ "$MODE" == "local" ]]; then
  # connection info precedence: command line > --dsn/$BELPHEGOR_PG_DSN > config.json
  if [[ -z "$DSN" && -z "$HOST$USER$DBNAME" ]]; then
    [[ -n "${BELPHEGOR_PG_DSN:-}" ]] && DSN="$BELPHEGOR_PG_DSN"
  fi
  if [[ -z "$DSN" && -z "$HOST$USER$DBNAME" ]]; then
    cfg="${CONFIG:-config.json}"
    if [[ -f "$cfg" ]]; then
      info "Reading database settings from $cfg"
      apply_config_fields < <(read_config_json "$cfg")
    fi
  fi

  command -v psql >/dev/null 2>&1 || die "psql not found on this computer (install postgresql-client or use -m docker)"

  declare -a PSQL_ARGS=()
  if [[ -n "$DSN" ]]; then
    PSQL_ARGS=("$DSN")
    target="$DSN"
  else
    [[ -n "$USER"   ]] || die "Database user (-U) is missing, or there is no valid config.json/DSN"
    [[ -n "$DBNAME" ]] || die "Database name (-d) is missing, or there is no valid config.json/DSN"
    HOST="${HOST:-127.0.0.1}"; PORT="${PORT:-5432}"; SSLMODE="${SSLMODE:-disable}"
    PSQL_ARGS=(-h "$HOST" -p "$PORT" -U "$USER" -d "$DBNAME")
    [[ -n "$SSLMODE" ]] && export PGSSLMODE="$SSLMODE"
    [[ -n "$DBPASS" ]] && export PGPASSWORD="$DBPASS"
    target="$USER@$HOST:$PORT/$DBNAME"
  fi

  info "Target database: $target"
  if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "Reset the Belphegor password in this database? [y/N]" ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || die "Cancelled"
  fi

  if ! printf '%s\n' "$SQL" | psql "${PSQL_ARGS[@]}" -v ON_ERROR_STOP=1 -q >/dev/null; then
    die "Write failed. If you see a pgcrypto permission or missing error, use a role that can create extensions, or run CREATE EXTENSION pgcrypto yourself first."
  fi

else
  # ---- docker ----
  command -v docker >/dev/null 2>&1 || die "docker not found"
  CONTAINER="${CONTAINER:-postgres}"

  # choose the exec method: prefer docker compose exec (service name), otherwise docker exec (container name)
  if [[ -z "$EXEC_KIND" ]]; then
    if docker compose version >/dev/null 2>&1 && [[ -f docker-compose.yml ]]; then
      EXEC_KIND="compose"
    else
      EXEC_KIND="docker"
    fi
  fi

  # psql credentials inside the container: command line first, then POSTGRES_* in .env, finally the compose default (belphegor)
  if [[ -f .env ]]; then
    # shellcheck disable=SC1091
    set -a; . ./.env; set +a
  fi
  DUSER="${USER:-${POSTGRES_USER:-belphegor}}"
  DNAME="${DBNAME:-${POSTGRES_DB:-belphegor}}"
  [[ -n "$DBPASS" ]] && export PGPASSWORD="$DBPASS"
  [[ -z "${PGPASSWORD:-}" && -n "${POSTGRES_PASSWORD:-}" ]] && export PGPASSWORD="$POSTGRES_PASSWORD"

  info "Target: psql -U $DUSER -d $DNAME inside container $CONTAINER (exec=$EXEC_KIND)"
  if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "Reset the Belphegor password in this container database? [y/N]" ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || die "Cancelled"
  fi

  # -e gives only the name, not the value -> it inherits from the current environment, so the password never appears in the docker command argv.
  declare -a EXEC_CMD
  if [[ "$EXEC_KIND" == "compose" ]]; then
    EXEC_CMD=(docker compose exec -T -e BELPHEGOR_RESET_NEWPASS -e PGPASSWORD "$CONTAINER"
              psql -U "$DUSER" -d "$DNAME" -v ON_ERROR_STOP=1 -q)
  else
    EXEC_CMD=(docker exec -i -e BELPHEGOR_RESET_NEWPASS -e PGPASSWORD "$CONTAINER"
              psql -U "$DUSER" -d "$DNAME" -v ON_ERROR_STOP=1 -q)
  fi

  if ! printf '%s\n' "$SQL" | "${EXEC_CMD[@]}" >/dev/null; then
    die "Write failed. Check the container name (-c), the database account (POSTGRES_* in .env), and the role's pgcrypto permission."
  fi
fi

unset BELPHEGOR_RESET_NEWPASS
echo "✓ Belphegor admin password reset. Log in with username Belphegor and the new password (no service restart needed)."
echo "  All previously issued login sessions (tokens) will be invalidated within a few seconds. If you are recovering from a hijacked or leaked account, also review custom tool, MCP, LLM and notification settings."
