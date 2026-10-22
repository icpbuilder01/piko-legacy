import { getCanisterEnv } from "@icp-sdk/core/agent/canister-env";

interface CanisterEnv {
  readonly "PUBLIC_CANISTER_ID:legacy": string;
  readonly "PUBLIC_CANISTER_ID:legacy-frontend": string;
  readonly "PUBLIC_CANISTER_ID:test-ledger": string;
}

export const canisterEnv = getCanisterEnv<CanisterEnv>();

export const legacyCanisterId = canisterEnv["PUBLIC_CANISTER_ID:legacy"];
// This canister's own id, used by auth.ts to pin Internet Identity
// derivation to one origin (icp.net vs icp0.io).
export const selfCanisterId = canisterEnv["PUBLIC_CANISTER_ID:legacy-frontend"];
export const rootKey = canisterEnv.IC_ROOT_KEY;

const isLocal = window.location.hostname.endsWith("localhost");

// The real, live PIKO ledger on mainnet. legacy itself defaults to this
// same id and is only redirected to test-ledger for local development.
const REAL_PIKO_LEDGER_CANISTER_ID = "56aad-fiaaa-aaaaj-qsefa-cai";
export const ledgerCanisterId = isLocal
  ? canisterEnv["PUBLIC_CANISTER_ID:test-ledger"]
  : REAL_PIKO_LEDGER_CANISTER_ID;
