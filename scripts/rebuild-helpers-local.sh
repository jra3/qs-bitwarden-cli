#!/usr/bin/env bash
# Run the pinned helper build from any checkout, including a linked worktree.
#
# scripts/build-agent.sh is the one definition of the release build, and when
# run outside the pinned image it re-executes itself inside the image with the
# checkout bind-mounted. That works for a primary clone and fails for a linked
# worktree: its `.git` is a file naming a gitdir under the primary clone's
# `.git/worktrees/`, which is outside the mount, so `git archive HEAD` in the
# container finds no repository. It also leaves root-owned files behind in
# `bin/` and `target/`, because the image runs as root.
#
# This wrapper does the export on the host instead: it clones HEAD into a
# fresh temporary directory, runs build-agent.sh in the pinned image there as
# the invoking user, and in `write` mode copies the result back into bin/.
# build-agent.sh is not changed, so what it builds here is what CI builds.
#
# Only the committed tree is built (build-agent.sh exports HEAD, never the
# working tree). Commit source changes to vault/, unlock-key/ or agent/ first;
# a dirty tree is reported, not built.

set -o pipefail
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# All scratch space lives inside the checkout, never in /tmp or ~/.cache.
STATE_DIR="$REPO_ROOT/.rebuild-helpers"
BUILD_SCRIPT="$REPO_ROOT/scripts/build-agent.sh"
OUTPUT_ARCH="x86_64-linux"

usage() {
  cat <<'USAGE'
Usage: scripts/rebuild-helpers-local.sh [compare|write|verify|test] [--ref <rev>]

  compare   (default) Build HEAD in the pinned image and report whether every
            tracked helper in bin/ matches, byte for byte. Writes nothing.
  write     Build HEAD in the pinned image and replace bin/x86_64-linux/* and
            bin/SHA256SUMS with the result. Commit them together.
  verify    Build HEAD twice from different paths and require identical
            output (build-agent.sh --verify-reproducible). Writes nothing.
  test      Run `cargo test --locked --all-targets` for agent/, unlock-key/
            and vault/ in the same pinned image. Writes nothing.
  --ref     Build this commit instead of HEAD.

Needs docker (or passwordless `sudo docker`) and the network, for the image
pull and the crate registry. Everything is written under .rebuild-helpers/ in
this checkout (ignored by git): the temporary clone, removed on exit, and the
registry cache, kept so later runs download nothing; delete it to start clean.
USAGE
}

fail() { printf 'rebuild-helpers-local: %s\n' "$1" >&2; exit 1; }
note() { printf 'rebuild-helpers-local: %s\n' "$1" >&2; }

# The same image build-agent.sh pins, read from the script so the two cannot
# drift apart.
pinned_image() {
  grep -oP '^PINNED_IMAGE="\K[^"]+' "$BUILD_SCRIPT"
}

container_runtime() {
  if docker info >/dev/null 2>&1; then echo "docker"; return 0; fi
  if sudo -n docker info >/dev/null 2>&1; then echo "sudo docker"; return 0; fi
  fail "no usable docker; build-agent.sh needs the pinned image"
}

main() {
  local mode="compare" ref="HEAD"
  while [ $# -gt 0 ]; do
    case "$1" in
      compare|write|verify|test) mode="$1" ;;
      --ref) shift; [ $# -gt 0 ] || fail "--ref needs a revision"; ref="$1" ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; fail "unknown argument '$1'" ;;
    esac
    shift
  done

  [ -x "$BUILD_SCRIPT" ] || fail "$BUILD_SCRIPT is missing"
  local image runtime commit
  image="$(pinned_image)" || fail "could not read PINNED_IMAGE from build-agent.sh"
  runtime="$(container_runtime)"
  commit="$(git -C "$REPO_ROOT" rev-parse --verify "$ref^{commit}")" \
    || fail "'$ref' is not a commit"

  if [ "$ref" = "HEAD" ] && [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]; then
    note "WARNING: the working tree has uncommitted changes; only commit $commit is built"
  fi

  # A self-contained clone, so `git archive HEAD` works inside the container
  # whatever shape the checkout outside it has. The temporary directory is
  # the only host path the container sees besides the registry cache.
  local work
  mkdir -p "$STATE_DIR" || fail "could not create $STATE_DIR"
  work="$(mktemp -d "$STATE_DIR/work.XXXXXX")" || fail "could not create a work directory"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT
  git clone -q --no-checkout "$REPO_ROOT" "$work/repo" || fail "could not clone $REPO_ROOT"
  git -C "$work/repo" checkout -q --detach "$commit" || fail "could not check out $commit"
  note "building $commit from $work/repo in $image"

  # As the invoking user, so nothing root-owned lands in the temporary clone
  # or the registry cache. The image's CARGO_HOME and RUSTUP_HOME are
  # world-writable, which is what lets rustup fetch the pinned toolchain's
  # components (rust-toolchain.toml names clippy) as that user. The image has
  # no passwd entry for that uid, and ssh-keygen (which the agent's tests
  # drive against the real socket) refuses to run without one, so a minimal
  # passwd is generated here and mounted over the image's; HOME is the clone.
  # safe.directory covers the bind-mounted clone being owned by a uid git may
  # not match.
  # The registry cache is a host directory rather than a docker volume: a
  # volume is created root-owned, which the unprivileged build cannot write.
  # Its paths are remapped out of the binary by build-agent.sh.
  local cache="$STATE_DIR/cargo-registry"
  mkdir -p "$cache" || fail "could not create $cache"
  printf 'root:x:0:0:root:/root:/bin/bash\nbuild:x:%s:%s:build:/work:/bin/bash\n' \
    "$(id -u)" "$(id -g)" > "$work/passwd" || fail "could not write a passwd file"
  local script_args=() inner
  case "$mode" in
    compare) script_args=(--compare-tracked) ;;
    write)   script_args=() ;;
    verify)  script_args=(--verify-reproducible) ;;
    test)    ;;
  esac
  if [ "$mode" = "test" ]; then
    inner='rc=0; for p in agent unlock-key vault; do echo "=== cargo test ($p)"; ( cd "$p" && cargo test --locked --all-targets ) || rc=1; done; exit $rc'
  else
    inner="/work/scripts/build-agent.sh ${script_args[*]}"
  fi

  # shellcheck disable=SC2086
  $runtime run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/work \
    -e QSBW_PINNED_BUILD=1 \
    -e CARGO_TARGET_DIR=/work/.cargo-target \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
    -v "$work/repo:/work" -w /work \
    -v "$work/passwd:/etc/passwd:ro" \
    -v "$cache:/usr/local/cargo/registry" \
    "$image" \
    bash -c "$inner"
  local rc=$?
  [ "$rc" -eq 0 ] || fail "the container run exited $rc"

  if [ "$mode" = "write" ]; then
    local name
    mkdir -p "$REPO_ROOT/bin/$OUTPUT_ARCH" || fail "could not create bin/$OUTPUT_ARCH"
    for name in "$work/repo/bin/$OUTPUT_ARCH"/*; do
      install -m 0755 "$name" "$REPO_ROOT/bin/$OUTPUT_ARCH/$(basename "$name")" \
        || fail "could not install $(basename "$name")"
    done
    install -m 0644 "$work/repo/bin/SHA256SUMS" "$REPO_ROOT/bin/SHA256SUMS" \
      || fail "could not install SHA256SUMS"
    note "wrote bin/$OUTPUT_ARCH/* and bin/SHA256SUMS from $commit:"
    cat "$REPO_ROOT/bin/SHA256SUMS"
    git -C "$REPO_ROOT" status --short -- bin/
  fi
}

main "$@"
