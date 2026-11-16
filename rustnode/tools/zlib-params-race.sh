#!/usr/bin/env bash
# Measures how often the pinned oracle is nondeterministic on the ordering
# `lib/zlib.js` reaches when `params()` is called on a live deflate stream.
#
#   ./tools/zlib-params-race.sh                 # 30 runs on each runtime
#   ./tools/zlib-params-race.sh --runs 100      # more samples
#   ./tools/zlib-params-race.sh --loaded        # saturate the CPUs first
#   ./tools/zlib-params-race.sh --tpool 1       # UV_THREADPOOL_SIZE for the oracle
#
# # Why this is not in tools/check.sh
#
# The oracle's answer is a coin flip. A gate step would flake on exactly the
# runs where the race goes the other way, and a retry loop would hide the one
# fact worth knowing. This script therefore reports a distribution and always
# exits 0 unless it cannot run at all; it asserts nothing about which side is
# "correct".
#
# # What it shows
#
# Node's own comment at `vendor/libnode-js/lib/zlib.js:788-791` says the native
# `params()` "should not happen while a write is currently in progress on the
# threadpool". `Zlib.prototype.params` reaches that state anyway. On the oracle
# the outcome is then a scheduling race: `OK`, `Z_STREAM_ERROR`, `Z_OK`,
# `Z_BUF_ERROR`, a segfault on a libuv worker thread, or a hang.
#
# rustnode runs the queued step before answering `params()`, which makes the
# window deterministic and takes the majority outcome. That is deliberate; see
# the module docs in `crates/rn-bind-zlib/src/handle.rs` and "params() after a
# flush is racy on the oracle" in docs/compat-status.md.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

runs=30
timeout_s=10
tpool=""
loaded=0

while [ $# -gt 0 ]; do
  case "$1" in
    --runs) runs="${2:?--runs needs a count}"; shift 2 ;;
    --timeout) timeout_s="${2:?--timeout needs seconds}"; shift 2 ;;
    --tpool) tpool="${2:?--tpool needs a size}"; shift 2 ;;
    --loaded) loaded=1; shift ;;
    -h | --help) sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "zlib-params-race: unknown argument: $1" >&2; exit 1 ;;
  esac
done

# Resolve the oracle the same way tools/fetch-node-oracle.sh does: the `[node]`
# table only, never a bare key scan that could pick up `[counts]`.
pin_value() {
  awk -v want="$1" '
    /^[[:space:]]*\[/ { section = $0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section); next }
    section == "node" {
      key = $0; sub(/[[:space:]]*=.*$/, "", key); gsub(/^[[:space:]]+/, "", key)
      if (key != want) next
      value = $0; sub(/^[^=]*=[[:space:]]*"/, "", value); sub(/".*$/, "", value)
      print value; exit
    }
  ' tools/node-pin.toml
}

pin_dir="$(pin_value oracle)"
pin_version="$(pin_value oracle_version)"
oracle_bin="${RN_NODE_ORACLE:-${pin_dir%/}/bin/node}"
if [ ! -x "$oracle_bin" ]; then
  echo "zlib-params-race: no oracle at $oracle_bin. Run ./tools/fetch-node-oracle.sh." >&2
  exit 1
fi
have_version="$("$oracle_bin" --version 2>/dev/null || true)"
if [ "$have_version" != "$pin_version" ]; then
  echo "zlib-params-race: $oracle_bin reports ${have_version:-nothing}," >&2
  echo "zlib-params-race: the pin wants $pin_version. Refusing to measure a" >&2
  echo "zlib-params-race: different engine; set RN_NODE_ORACLE to the pinned build." >&2
  exit 1
fi
rustnode_bin="$root/target/release/rustnode"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
load_pids=""

stop_load() {
  [ -n "$load_pids" ] && kill -9 $load_pids 2>/dev/null
  load_pids=""
}
trap 'stop_load; rm -rf "$scratch"' EXIT

# The readable side must be drained, or the stream never emits 'end' and `OK`
# is unreachable no matter what the native side does.
cat >"$scratch/repro.js" <<'JS'
const zlib = require('zlib');
const d = zlib.createDeflate({ level: 1 });
let verdict = null;
const report = (line) => {
  if (verdict !== null) return;
  verdict = line;
  process.stdout.write(line + '\n');
};
d.on('data', () => {});
d.on('error', (e) => report('ERROR ' + e.code));
d.on('end', () => report('OK'));
d.write(Buffer.alloc(5000, 65));
// params() runs from the callback of an *async* flush write, after end() below
// has already queued its own Z_FINISH write behind that flush.
d.flush(zlib.constants.Z_SYNC_FLUSH, () => {
  d.params(9, 0);
  d.end(Buffer.alloc(100, 66));
});
JS

distribute() {
  local bin="$1" label="$2" env_prefix="$3"
  local out line status
  out="$scratch/dist"
  : >"$out"
  for _ in $(seq 1 "$runs"); do
    # `ulimit -c 0`: a segfault per run would otherwise leave a core file each
    # time. The signal still arrives through the wait status.
    line="$( (ulimit -c 0; exec env $env_prefix timeout -s KILL "$timeout_s" \
      "$bin" "$scratch/repro.js") 2>/dev/null )"
    status=$?
    if [ "$status" -eq 137 ]; then
      echo "TIMEOUT >${timeout_s}s"
    elif [ "$status" -ge 128 ]; then
      echo "CRASH $((status - 128))"
    elif [ -n "$line" ]; then
      echo "$line"
    elif [ "$status" -ne 0 ]; then
      echo "EXIT $status"
    else
      echo "SILENT"
    fi >>"$out"
  done
  printf '%s (%s runs)\n' "$label" "$runs"
  sort "$out" | uniq -c | sort -rn | sed 's/^/  /'
}

if [ "$loaded" -eq 1 ]; then
  # Busy-loop one worker per CPU so the load outlives the measurement without
  # blocking this script.
  for _ in $(seq 1 "$(nproc)"); do
    bash -c 'while :; do :; done' &
    load_pids="$load_pids $!"
  done
  sleep 2
  echo "load average: $(cut -d' ' -f1-3 /proc/loadavg)"
fi

echo "oracle:   $oracle_bin"
echo "rustnode: $rustnode_bin"
echo

distribute "$oracle_bin" "oracle${tpool:+ (UV_THREADPOOL_SIZE=$tpool)}" \
  "${tpool:+UV_THREADPOOL_SIZE=$tpool }"

if [ ! -x "$rustnode_bin" ]; then
  echo "rustnode: $rustnode_bin is absent; build it with" >&2
  echo "  RUSTUP_TOOLCHAIN=1.96.1 CXX=g++ cargo build --release -p rn-cli" >&2
else
  echo
  distribute "$rustnode_bin" "rustnode" ""
fi

echo
echo "A distribution, not a verdict: the oracle's answer here is a race, and"
echo "rustnode deliberately takes the majority outcome. See docs/compat-status.md."
