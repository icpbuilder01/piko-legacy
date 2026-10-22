import { MasterPublicKey, MasterPublicKeyId } from "@dfinity/vetkeys";
import { Principal } from "@icp-sdk/core/principal";
import { legacyCanisterId } from "./canister-env";
import { ok, type Legacy } from "./session";

let cached: Promise<Uint8Array> | null = null;

/**
 * The vetKD public key vaults are encrypted to. For the mainnet keys it is
 * also derived offline from the IC's published master key, so the browser
 * never encrypts to a key the canister merely claims is right.
 */
export function vaultPublicKey(actor: Legacy): Promise<Uint8Array> {
  if (!cached) {
    cached = (async () => {
      const [config, stored] = await Promise.all([actor.getConfig(), actor.getPublicKey()]);
      const key = stored ?? ok(await actor.fetchPublicKey());
      const master =
        config.keyName === "key_1" ? MasterPublicKeyId.KEY_1 : config.keyName === "test_key_1" ? MasterPublicKeyId.TEST_KEY_1 : null;
      if (master) {
        const expected = MasterPublicKey.productionKey(master)
          .deriveCanisterKey(Principal.fromText(legacyCanisterId).toUint8Array())
          .deriveSubKey(config.context)
          .publicKeyBytes();
        if (expected.length !== key.length || expected.some((b, i) => b !== key[i])) {
          throw new Error("The vault service returned an unexpected encryption key. Nothing was encrypted.");
        }
      }
      return key;
    })();
    cached.catch(() => (cached = null));
  }
  return cached;
}
