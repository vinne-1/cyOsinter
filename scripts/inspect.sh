#!/usr/bin/env bash
# inspect.sh — Full verification suite for Cyber-Shield-Pro
# Mirrors the claw-code green-level contract: all three must pass before merge.
#
# Usage:
#   bash scripts/inspect.sh          # run all checks
#   bash scripts/inspect.sh --unit   # TypeScript + unit tests only (no E2E)
#   bash scripts/inspect.sh --e2e    # E2E only (assumes server is running)

set -euo pipefail

UNIT_ONLY=false
E2E_ONLY=false
for arg in "$@"; do
  case $arg in
    --unit) UNIT_ONLY=true ;;
    --e2e)  E2E_ONLY=true ;;
  esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; exit 1; }
info() { echo -e "${BLUE}→${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }

echo ""
echo "════════════════════════════════════════"
echo "  Cyber-Shield-Pro — Inspection Suite"
echo "════════════════════════════════════════"
echo ""

cd "$(dirname "$0")/.."

if [ "$E2E_ONLY" = false ]; then
  # 1. TypeScript
  info "TypeScript check..."
  if npx tsc --noEmit; then
    pass "TypeScript — clean"
  else
    fail "TypeScript — errors found"
  fi

  # 2. Unit tests
  info "Unit tests (Vitest)..."
  if npm test; then
    pass "Unit tests — all passed"
  else
    fail "Unit tests — failures found"
  fi
fi

if [ "$UNIT_ONLY" = false ]; then
  # 3. E2E tests
  info "E2E tests (Playwright)..."
  if npx playwright test --reporter=list; then
    pass "E2E tests — all passed"
  else
    warn "E2E tests failed — run: npx playwright show-report"
    exit 1
  fi
fi

echo ""
echo "════════════════════════════════════════"
echo -e "  ${GREEN}All checks passed — ready to commit${NC}"
echo "════════════════════════════════════════"
echo ""
