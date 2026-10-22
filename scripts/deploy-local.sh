#!/usr/bin/env bash
# Deploys PIKO Legacy to its own local ICP network (free, for development
# and the integration tests). Separate project on purpose -- see ../icp.yaml.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Starting local ICP network..."
icp network start -d

echo "==> Deploying test-ledger, legacy, legacy-frontend..."
icp deploy test-ledger legacy legacy-frontend -y

TEST_LEDGER_ID=$(icp canister status test-ledger -i)
echo "==> Local settings: test-ledger ($TEST_LEDGER_ID), local vetKD key, 60 s minimum interval..."
icp canister call legacy setPikoLedgerId "(principal \"$TEST_LEDGER_ID\")"
icp canister call legacy setKeyName '("dfx_test_key")' || true
icp canister call legacy setMinIntervalSec '(60)'
icp canister call legacy fetchPublicKey '()'

echo ""
echo "==> Open PIKO Legacy at: http://$(icp canister status legacy-frontend -i).localhost:8090/"
