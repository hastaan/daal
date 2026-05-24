#!/usr/bin/env bash
# tools/deploy-landing.sh — build landing/ and push to the `gh-pages`
# branch so GitHub Pages can serve it from
# https://hastaan.github.io/daal/.
#
# We use the gh-pages branch method rather than `/docs` on main because
# `docs/` already contains markdown documentation (handovers, threat
# model, ADRs) that we don't want to mix with the static landing site.
#
# The deploy goes through a worktree on /tmp so the working tree of
# main is never touched.
#
# Usage:
#   bash tools/deploy-landing.sh           # build + commit + push gh-pages
#   bash tools/deploy-landing.sh --dry-run # build only, don't push
#
# First-time setup on github.com:
#   Settings → Pages → Source: "Deploy from a branch"
#                     → Branch: gh-pages / (root) → Save
#
# After the first push the site goes live at
# https://hastaan.github.io/daal/ in about a minute.

set -euo pipefail

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LANDING="$ROOT/landing"
WORKTREE="$(mktemp -d -t daal-ghpages-XXXX)"
trap 'echo "==> cleanup worktree $WORKTREE"; git -C "$ROOT" worktree remove --force "$WORKTREE" 2>/dev/null || rm -rf "$WORKTREE"' EXIT

if [ ! -d "$LANDING" ]; then
  echo "FATAL: $LANDING does not exist" >&2
  exit 1
fi

echo "==> npm install (landing/)"
( cd "$LANDING" && npm install --no-audit --no-fund )

echo "==> npm run build (landing/)"
( cd "$LANDING" && npm run build )

if [ "$DRY_RUN" = 1 ]; then
  echo "==> dry-run; skipping git work"
  echo "Built dist/ at $LANDING/dist:"
  ls -la "$LANDING/dist"
  exit 0
fi

cd "$ROOT"

# Ensure the gh-pages branch exists. If absent, create an empty orphan
# branch — gh-pages should NEVER carry main's source tree.
if ! git rev-parse --verify gh-pages >/dev/null 2>&1; then
  if git ls-remote --exit-code --heads origin gh-pages >/dev/null 2>&1; then
    echo "==> fetching existing remote gh-pages"
    git fetch origin gh-pages:gh-pages
  else
    echo "==> creating new orphan gh-pages branch"
    # Stage a worktree, init the orphan, drop one placeholder commit
    # so git worktree add can attach to it on subsequent runs.
    git worktree add --detach "$WORKTREE" HEAD >/dev/null
    (
      cd "$WORKTREE"
      git checkout --orphan gh-pages
      git rm -rf --cached . >/dev/null 2>&1 || true
      find . -mindepth 1 -maxdepth 1 -not -name '.git' -exec rm -rf {} +
      echo "Daal landing page — see https://hastaan.github.io/daal/" > README.md
      touch .nojekyll
      git add README.md .nojekyll
      GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-hastaan}" \
      GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-hastaan@gmail.com}" \
      GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-hastaan}" \
      GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-hastaan@gmail.com}" \
        git commit -m "init gh-pages branch"
    )
    git worktree remove --force "$WORKTREE"
  fi
fi

echo "==> checking out gh-pages into temporary worktree"
git worktree add "$WORKTREE" gh-pages

echo "==> wiping previous site contents"
find "$WORKTREE" -mindepth 1 -maxdepth 1 -not -name '.git' -exec rm -rf {} +

echo "==> copying landing/dist/ → worktree"
cp -R "$LANDING/dist/." "$WORKTREE/"

# .nojekyll disables Jekyll processing on GitHub Pages. Without it,
# Jekyll would refuse to serve any file/folder beginning with an
# underscore. Vite's hashed asset names don't use underscores but this
# is still the safest default.
touch "$WORKTREE/.nojekyll"

# CNAME (optional). Uncomment if you wire a custom domain.
# echo "daal.example.org" > "$WORKTREE/CNAME"

cd "$WORKTREE"
git add -A
if git diff --cached --quiet; then
  echo "==> no changes to publish; gh-pages already up to date"
  exit 0
fi
VERSION="$(cat "$ROOT/VERSION" 2>/dev/null || echo unknown)"
git commit -m "publish landing page (v$VERSION)"

echo "==> pushing gh-pages → origin"
echo "    (this command requires push permission on hastaan/daal)"
echo "    git push origin gh-pages"
echo ""
echo "If you'd rather review locally first, run the push by hand:"
echo "    cd $WORKTREE && git log -1 --stat"
echo "    git push origin gh-pages"
echo ""
read -r -p "Push now? [y/N] " ans
if [ "${ans:-N}" = "y" ] || [ "${ans:-N}" = "Y" ]; then
  git push origin gh-pages
  echo "==> pushed"
  echo ""
  echo "First-time GitHub Pages setup (only once per repo):"
  echo "  Settings → Pages → Source: 'Deploy from a branch'"
  echo "                  → Branch: gh-pages / (root) → Save"
  echo ""
  echo "Site URL: https://hastaan.github.io/daal/"
else
  echo "==> not pushed; gh-pages branch updated locally"
fi
