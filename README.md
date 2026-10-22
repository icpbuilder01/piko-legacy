# PIKO Legacy

A dead man's switch for secrets, on the Internet Computer. The owner writes a secret and names up to five heirs. If the owner stops checking in, the vault is released and each heir opens it with their private link. Until then nobody can read it: not the heirs, not the controllers, not the node operators.

Mainnet: `legacy` = vkxrn-3qaaa-aaaak-qzk6q-cai, `legacy-frontend` = vnwxz-wiaaa-aaaak-qzk6a-cai (https://vnwxz-wiaaa-aaaak-qzk6a-cai.icp.net/).

## Scheme

Everything is encrypted in the browser (`legacy-frontend/src/lib/vault-crypto.ts`):

```
secret --AES-GCM(K)--> ciphertext                                   stored once
K --AES-GCM(inner_i)--> --IBE(vault identity, vetKD key)--> wrappedKey_i    one per heir
inner_i = SHA-256("piko-legacy-inner" || s_i)     s_i: 32 random bytes, only in heir i's link (#fragment)
proof_i = SHA-256("piko-legacy-claim" || s_i)     the canister stores SHA-256(proof_i)
```

- Before release the IBE layer cannot be opened: `heirOpen` only asks the subnet for the vault's vetKey once `now >= lastCheckIn + interval`.
- After release the vetKey alone is useless: the inner layer needs `s_i`, which never reaches the canister.
- The vetKey is returned encrypted to a one-time transport key and verified in the browser against the canister's derived public key. For `key_1`/`test_key_1` the browser also derives that public key offline from the IC master key and refuses to encrypt if the canister disagrees.
- Release is computed from the clock (no timer). Once released, check-ins are refused for good. The owner can delete a vault at any time.

## Limits

5 heirs, 32 KB of ciphertext, 10 vaults per owner, 5,000 vaults in total. Each link opens 3 times, each vault 10 times (each open costs one vetKD derivation, ~26 B cycles on `key_1`). One-time fee in PIKO (ICRC-2), 1,000 PIKO on mainnet, paid to the canister and then split equally by `distributeFees` (run automatically after each new vault, callable by anyone) between `feeShareTargets`: the PikoDice (`7yyso-myaaa-aaaaj-qseia-cai`) and PikoBlackjack (`d76up-oaaaa-aaaai-ax4ia-cai`) bankrolls. Cycles for vetKey derivations are not funded by the fee: top the canister up.

## Controllers

`setFee` (max 100,000 PIKO), `setFeeRecipient`, `setFeeShareTargets`, `setPikoLedgerId`, `setKeyName` (frozen once any vault exists), `setDerivationCycles`, `setMinIntervalSec` (60 s minimum, 7 days by default), `withdrawFees`. No controller call can read or release a vault.

## Develop and test

```bash
scripts/deploy-local.sh                                # local network on port 8090, dfx_test_key, 60 s intervals
cd legacy-frontend && npx tsx test/e2e.ts              # 29 end-to-end checks, real vetKD + crypto (about 80 s)
cd legacy-frontend && npx vite --host 127.0.0.1        # dev server; open via http://localhost:<port>/?devid=<name> to log in as a local test key
```

## Verify the deployed code

The `legacy` build is reproducible. Build it and compare its hash with the module hash of the live canister:

```bash
icp build legacy
sha256sum .icp/cache/artifacts/legacy
icp canister status vkxrn-3qaaa-aaaak-qzk6q-cai -e ic   # "Module hash" must be the same
```

## License

MIT, see [LICENSE](LICENSE).
