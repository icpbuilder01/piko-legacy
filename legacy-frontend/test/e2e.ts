// End-to-end test against the LOCAL network only (scripts/deploy-local.sh
// first): real vetKD, real AES/IBE in the same code the browser runs, real
// fee payment on the local test-ledger. Takes a little over a minute
// because it waits for a vault to be released.
//
//   cd legacy-frontend && npx tsx test/e2e.ts
import { execSync } from "node:child_process";
import { HttpAgent } from "@icp-sdk/core/agent";
import { Ed25519KeyIdentity } from "@icp-sdk/core/identity";
import { createActor as createLegacy } from "../src/bindings/legacy/legacy";
import { createActor as createLedger } from "../src/bindings/ledger/ledger";
import { heirProof, newTransportKey, openVault, sealVault } from "../src/lib/vault-crypto";

const HOST = "http://localhost:8090";
const sh = (cmd: string) => execSync(cmd, { cwd: `${import.meta.dirname}/../..`, encoding: "utf-8" }).trim();
const LEGACY = sh("icp canister status legacy -i");
const LEDGER = sh("icp canister status test-ledger -i");
const E8S = 100_000_000n;
const FEE = 100n * E8S;

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail?: unknown) {
  if (cond) {
    pass++;
    console.log(`  ok   ${name}`);
  } else {
    fail++;
    console.log(`  FAIL ${name}`, detail ?? "");
  }
}
const isErr = (r: { __kind__: string }, text?: string) =>
  r.__kind__ === "err" && (!text || (r as { err: string }).err.toLowerCase().includes(text.toLowerCase()));

async function as(seed?: string) {
  const identity = seed ? Ed25519KeyIdentity.generate(new TextEncoder().encode(seed.padEnd(32, "#").slice(0, 32))) : undefined;
  const agent = await HttpAgent.create({ host: HOST, identity, shouldFetchRootKey: true });
  return { principal: identity?.getPrincipal(), legacy: createLegacy(LEGACY, { agent }), ledger: createLedger(LEDGER, { agent }) };
}

const run = Date.now().toString(36);
const owner = await as(`e2e-owner-${run}`);
const other = await as(`e2e-other-${run}`);
const anon = await as();

console.log("== setup");
sh(`icp canister call legacy setFee '(${FEE} : nat)'`);
sh(`icp canister call test-ledger icrc1_transfer '(record { to = record { owner = principal "${owner.principal!.toText()}" }; amount = ${1000n * E8S} : nat })'`);
const pk = (await owner.legacy.fetchPublicKey()) as { __kind__: "ok"; ok: Uint8Array };
check("vetKD public key available", pk.__kind__ === "ok" && pk.ok.length === 96);
const publicKey = pk.ok;

console.log("== create");
const text = "seed: abandon abandon ... art\nbank PIN 1234 — é€ ok";
const sealed = await sealVault(publicKey, text, ["Alice", "Bob"]);
const args = {
  title: "My keys",
  ibeId: sealed.ibeId,
  ciphertext: sealed.ciphertext,
  intervalSec: 60n,
  heirs: sealed.heirs.map((h) => ({ name: h.name, claimHash: h.claimHash, wrappedKey: h.wrappedKey })),
};
check("ciphertext does not contain the text", !Buffer.from(sealed.ciphertext).toString("latin1").includes("abandon"));
check("anonymous cannot create", isErr(await anon.legacy.createVault(args), "log in"));
check("create without approval refused", isErr(await owner.legacy.createVault(args), "not approved"));
await new Promise((r) => setTimeout(r, 3200));
const approve = await owner.ledger.icrc2_approve({ spender: { owner: (await import("@icp-sdk/core/principal")).Principal.fromText(LEGACY) }, amount: FEE + 10_000n });
check("approve", "Ok" in (approve as object) || (approve as { __kind__?: string }).__kind__ === "Ok", approve);
const created = await owner.legacy.createVault(args);
check("create with approval", created.__kind__ === "ok", created);
const id = (created as { ok: bigint }).ok;
const bal = await owner.ledger.icrc1_balance_of({ owner: owner.principal! });
check("fee charged (100 + 2 ledger fees)", bal === 1000n * E8S - FEE - 20_000n, bal);
await new Promise((r) => setTimeout(r, 4000));
const targets = (await owner.legacy.getConfig()).feeShareTargets;
const shares = await Promise.all(targets.map((t) => owner.ledger.icrc1_balance_of({ owner: t })));
check("fee split 50/50 to the share targets", targets.length === 2 && shares.every((b) => b === FEE / 2n - 10_000n), shares);
check("nothing left on the vault canister", (await owner.ledger.icrc1_balance_of({ owner: (await import("@icp-sdk/core/principal")).Principal.fromText(LEGACY) })) === 0n);
await new Promise((r) => setTimeout(r, 3200));
check("same identity cannot be reused", isErr(await owner.legacy.createVault(args), "already used"));

const mine = await owner.legacy.myVaults();
check("owner sees the vault, not released", mine.length === 1 && !mine[0].released && mine[0].heirs.length === 2);
check("other user sees nothing", (await other.legacy.myVaults()).length === 0);
check("other user cannot delete", isErr(await other.legacy.deleteVault(id), "not your vault"));

console.log("== heirs before release");
const proofA = await heirProof(sealed.heirs[0].secret);
const proofB = await heirProof(sealed.heirs[1].secret);
const look = await anon.legacy.heirLookup(id, proofA);
check("heir link recognised", look.__kind__ === "ok" && look.ok.heirName === "Alice" && !look.ok.released, look);
check("random link refused", isErr(await anon.legacy.heirLookup(id, crypto.getRandomValues(new Uint8Array(32))), "does not match"));
const tsk0 = newTransportKey();
check("open before release refused", isErr(await anon.legacy.heirOpen(id, proofA, tsk0.publicKeyBytes()), "not released"));
check("check-in works before release", (await owner.legacy.checkIn()) === 1n);

console.log("== waiting 62 s for release...");
await new Promise((r) => setTimeout(r, 62_000));
check("check-in refused after release", (await owner.legacy.checkIn()) === 0n);
check("setInterval refused after release", isErr(await owner.legacy.setInterval(id, 3600n), "released"));
const look2 = await anon.legacy.heirLookup(id, proofB);
check("released", look2.__kind__ === "ok" && look2.ok.released);

console.log("== heirs after release");
const tskA = newTransportKey();
const openedA = await anon.legacy.heirOpen(id, proofA, tskA.publicKeyBytes());
check("Alice opens", openedA.__kind__ === "ok", openedA);
if (openedA.__kind__ === "ok") {
  check("Alice decrypts the exact text", (await openVault(publicKey, tskA, openedA.ok, sealed.heirs[0].secret)) === text);
  let bobOnAlice = "";
  try {
    bobOnAlice = await openVault(publicKey, tskA, openedA.ok, sealed.heirs[1].secret);
  } catch {
    bobOnAlice = "refused";
  }
  check("Bob's secret cannot open Alice's copy", bobOnAlice === "refused");
  let wrongTsk = "";
  try {
    wrongTsk = await openVault(publicKey, newTransportKey(), openedA.ok, sealed.heirs[0].secret);
  } catch {
    wrongTsk = "refused";
  }
  check("vetKey useless without the transport key that asked for it", wrongTsk === "refused");
}
const tskB = newTransportKey();
const openedB = await other.legacy.heirOpen(id, proofB, tskB.publicKeyBytes());
check("Bob opens (from any account)", openedB.__kind__ === "ok" && (await openVault(publicKey, tskB, openedB.ok, sealed.heirs[1].secret)) === text);

for (let i = 0; i < 2; i++) await anon.legacy.heirOpen(id, proofA, newTransportKey().publicKeyBytes());
check("open cap (3 per link)", isErr(await anon.legacy.heirOpen(id, proofA, newTransportKey().publicKeyBytes()), "too many"));
check("bad transport key refused", isErr(await anon.legacy.heirOpen(id, proofB, new Uint8Array(10)), "transport"));

console.log("== delete");
check("owner deletes", (await owner.legacy.deleteVault(id)).__kind__ === "ok");
check("links dead after delete", isErr(await anon.legacy.heirLookup(id, proofA), "does not exist"));

sh(`icp canister call legacy setFee '(0 : nat)'`);
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
