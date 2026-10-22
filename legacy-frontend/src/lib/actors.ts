import type { Identity } from "@icp-sdk/core/agent";
import { createActor as createLedgerActor } from "../bindings/ledger/ledger";
import { createActor as createLegacyActor } from "../bindings/legacy/legacy";
import { legacyCanisterId, ledgerCanisterId, rootKey } from "./canister-env";

export function getLegacyActor(identity?: Identity) {
  return createLegacyActor(legacyCanisterId, { agentOptions: { rootKey, identity } });
}

export function getLedgerActor(identity?: Identity) {
  return createLedgerActor(ledgerCanisterId, { agentOptions: { rootKey, identity } });
}
