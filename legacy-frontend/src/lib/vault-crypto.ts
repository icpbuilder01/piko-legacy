// All the cryptography of PIKO Legacy, in the browser. See the comment at
// the top of ../../../legacy/src/main.mo for the scheme. Nothing secret
// (the text, K, or a heir secret s) ever leaves this module unencrypted,
// except s inside the heir link the owner copies.
import {
  DerivedPublicKey,
  EncryptedVetKey,
  IbeCiphertext,
  IbeIdentity,
  IbeSeed,
  TransportSecretKey,
} from "@dfinity/vetkeys";

const enc = new TextEncoder();
const dec = new TextDecoder();

function random(n: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(n));
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

async function sha256(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as Uint8Array<ArrayBuffer>));
}

async function aesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as Uint8Array<ArrayBuffer>, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** iv (12 bytes) || AES-256-GCM ciphertext+tag */
async function seal(raw: Uint8Array, data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const iv = random(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(raw), data as Uint8Array<ArrayBuffer>);
  return concat(iv, new Uint8Array(ct));
}

async function unseal(raw: Uint8Array, box: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: box.slice(0, 12) },
    await aesKey(raw),
    box.slice(12) as Uint8Array<ArrayBuffer>
  );
  return new Uint8Array(pt);
}

export function toB64Url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64Url(text: string): Uint8Array<ArrayBuffer> {
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

const innerKey = (s: Uint8Array) => sha256(concat(enc.encode("piko-legacy-inner"), s));

/** What a heir sends to prove they hold the link. The canister stores sha256(proof). */
export const heirProof = (s: Uint8Array) => sha256(concat(enc.encode("piko-legacy-claim"), s));

export interface SealedHeir {
  name: string;
  claimHash: Uint8Array<ArrayBuffer>;
  wrappedKey: Uint8Array<ArrayBuffer>;
  secret: Uint8Array<ArrayBuffer>; // goes into the heir's link only
}

export interface SealedVault {
  ibeId: Uint8Array<ArrayBuffer>;
  ciphertext: Uint8Array<ArrayBuffer>;
  heirs: SealedHeir[];
}

/** Encrypts `text` for `heirNames`, to the vault service's vetKD public key. */
export async function sealVault(publicKey: Uint8Array, text: string, heirNames: string[]): Promise<SealedVault> {
  const dpk = DerivedPublicKey.deserialize(publicKey);
  const ibeId = random(32);
  const identity = IbeIdentity.fromBytes(ibeId);
  const k = random(32);
  const ciphertext = await seal(k, enc.encode(JSON.stringify({ v: 1, text })));
  const heirs: SealedHeir[] = [];
  for (const name of heirNames) {
    const secret = random(32);
    const inner = await seal(await innerKey(secret), k);
    const wrappedKey = IbeCiphertext.encrypt(dpk, identity, inner, IbeSeed.random()).serialize() as Uint8Array<ArrayBuffer>;
    heirs.push({ name, claimHash: await sha256(await heirProof(secret)), wrappedKey, secret });
  }
  return { ibeId, ciphertext, heirs };
}

export function newTransportKey(): TransportSecretKey {
  return TransportSecretKey.random();
}

/** Decrypts what heirOpen returned, with the heir's link secret. */
export async function openVault(
  publicKey: Uint8Array,
  tsk: TransportSecretKey,
  opened: { ibeId: Uint8Array; ciphertext: Uint8Array; wrappedKey: Uint8Array; encryptedVetKey: Uint8Array },
  secret: Uint8Array
): Promise<string> {
  const dpk = DerivedPublicKey.deserialize(publicKey);
  // Verifies the key really is the subnet's signature on this vault's identity.
  const vetKey = EncryptedVetKey.deserialize(opened.encryptedVetKey).decryptAndVerify(tsk, dpk, opened.ibeId);
  const inner = IbeCiphertext.deserialize(opened.wrappedKey).decrypt(vetKey);
  const k = await unseal(await innerKey(secret), inner);
  const body = JSON.parse(dec.decode(await unseal(k, opened.ciphertext))) as { v: number; text: string };
  return body.text;
}
