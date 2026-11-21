#!/usr/bin/env bash
# Build locally, or push one explicitly named temporary worktree without force.
set -euo pipefail
action="$1"
version="$2"
tree="$3"
[[ "$version" =~ ^[a-f0-9]{64}$ ]]
branch=refs/heads/rewrite-publications
case "$action" in
  build)
    refs="$(git ls-remote origin "$branch")"
    base="$(git rev-parse HEAD)"
    if [[ -n "$refs" ]]; then
      git fetch --no-tags --depth=1 origin "$branch"
      base="$(git rev-parse FETCH_HEAD)"
    fi
    git worktree add --detach "$tree" "$base"
    mkdir -p "$tree/published"
    python3 scripts/publish_rewrite.py publish "$version" --output "$tree/published"
    git -C "$tree" add -- "published/GoogleRedirect/$version"
    git -C "$tree" -c user.name=github-actions -c user.email=41898282+github-actions[bot]@users.noreply.github.com commit -m "Publish GoogleRedirect $version"
    ;;
  push)
    git -C "$tree" -c credential.helper='!gh auth git-credential' push origin "HEAD:$branch"
    ;;
  *)
    exit 2
    ;;
esac
