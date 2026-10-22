import Principal "mo:core/Principal";
import Nat "mo:core/Nat";
import Int "mo:core/Int";
import Text "mo:core/Text";
import Time "mo:core/Time";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Map "mo:core/Map";
import Result "mo:core/Result";
import Error "mo:core/Error";
import Cycles "mo:core/Cycles";
import Timer "mo:core/Timer";
import Sha256 "mo:sha2/Sha256";

// PIKO Legacy: a dead man's switch for secrets.
//
// The owner writes a secret in the browser and names up to five heirs.
// Everything is encrypted in the browser before it reaches this canister:
//
//   secret --AES-GCM(K)--> ciphertext                      (stored once)
//   K --AES-GCM(inner_i)--> --IBE(vault identity)--> wrappedKey_i   (one per heir)
//
// inner_i comes from a random secret s_i that only lives in heir i's link
// (in the URL fragment, never sent anywhere). The IBE layer can only be
// opened with a vetKey for the vault's identity, and this canister only
// asks the subnet for that vetKey once the vault is released: the owner
// has not checked in for `intervalNs`. So:
//  - before release, the link alone is useless (IBE layer is closed);
//  - after release, the vetKey alone is useless (inner layer needs s_i);
//  - this canister, its controllers and the node operators never see the
//    secret, K or any s_i. Heirs prove they hold a link with
//    proof = SHA-256("piko-legacy-claim" || s_i); only SHA-256(proof) is stored.
//
// Release is computed from the clock, not by a timer: once the deadline
// has passed, the vault is released for good and check-ins are refused.
actor self {

  type R<T> = Result.Result<T, Text>;

  public type HeirIn = { name : Text; claimHash : Blob; wrappedKey : Blob };

  type Heir = { name : Text; claimHash : Blob; wrappedKey : Blob; opens : Nat };

  type Vault = {
    id : Nat;
    owner : Principal;
    title : Text;
    ibeId : Blob;
    ciphertext : Blob;
    heirs : [Heir];
    createdAt : Int;
    lastCheckIn : Int;
    intervalNs : Int;
    feePaidE8s : Nat;
  };

  public type CreateArgs = {
    title : Text;
    ibeId : Blob;
    ciphertext : Blob;
    intervalSec : Nat;
    heirs : [HeirIn];
  };

  public type OwnerView = {
    id : Nat;
    title : Text;
    createdAt : Int;
    lastCheckIn : Int;
    intervalSec : Nat;
    deadline : Int;
    released : Bool;
    heirs : [{ name : Text; opens : Nat }];
    secretBytes : Nat;
  };

  public type HeirView = {
    title : Text;
    heirName : Text;
    deadline : Int;
    released : Bool;
    opensLeft : Nat;
  };

  public type Opened = {
    ibeId : Blob;
    ciphertext : Blob;
    wrappedKey : Blob;
    encryptedVetKey : Blob;
  };

  public type Config = {
    feeE8s : Nat;
    ledger : Principal;
    feeRecipient : Principal;
    feeShareTargets : [Principal];
    sharedE8s : Nat;
    keyName : Text;
    context : Blob;
    minIntervalSec : Nat;
    maxIntervalSec : Nat;
    maxHeirs : Nat;
    maxSecretBytes : Nat;
    maxVaultsPerOwner : Nat;
    maxOpensPerHeir : Nat;
    vaultCount : Nat;
  };

  type Account = { owner : Principal; subaccount : ?Blob };
  type TransferFromError = {
    #BadFee : { expected_fee : Nat };
    #BadBurn : { min_burn_amount : Nat };
    #InsufficientFunds : { balance : Nat };
    #InsufficientAllowance : { allowance : Nat };
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #TemporarilyUnavailable;
    #GenericError : { error_code : Nat; message : Text };
  };
  type TransferError = {
    #BadFee : { expected_fee : Nat };
    #BadBurn : { min_burn_amount : Nat };
    #InsufficientFunds : { balance : Nat };
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #TemporarilyUnavailable;
    #GenericError : { error_code : Nat; message : Text };
  };
  type Ledger = actor {
    icrc1_fee : () -> async Nat;
    icrc1_balance_of : (Account) -> async Nat;
    icrc2_transfer_from : ({
      spender_subaccount : ?Blob;
      from : Account;
      to : Account;
      amount : Nat;
      fee : ?Nat;
      memo : ?Blob;
      created_at_time : ?Nat64;
    }) -> async { #Ok : Nat; #Err : TransferFromError };
    icrc1_transfer : ({
      from_subaccount : ?Blob;
      to : Account;
      amount : Nat;
      fee : ?Nat;
      memo : ?Blob;
      created_at_time : ?Nat64;
    }) -> async { #Ok : Nat; #Err : TransferError };
  };

  type VetKdKeyId = { curve : { #bls12_381_g2 }; name : Text };
  type Management = actor {
    vetkd_public_key : ({ canister_id : ?Principal; context : Blob; key_id : VetKdKeyId }) -> async { public_key : Blob };
    vetkd_derive_key : ({ input : Blob; context : Blob; transport_public_key : Blob; key_id : VetKdKeyId }) -> async { encrypted_key : Blob };
  };
  transient let ic : Management = actor "aaaaa-aa";

  transient let E8S : Nat = 100_000_000;
  transient let SEC : Int = 1_000_000_000;
  transient let DAY_SEC : Nat = 86_400;
  transient let HARD_MIN_INTERVAL_SEC : Nat = 60;
  transient let MAX_INTERVAL_SEC : Nat = 3_650 * DAY_SEC;
  transient let HARD_MAX_FEE : Nat = 100_000 * E8S;
  transient let MAX_HEIRS : Nat = 5;
  transient let MAX_SECRET_BYTES : Nat = 32 * 1024; // ciphertext, i.e. secret + 28 bytes of AES-GCM overhead
  transient let MAX_WRAPPED_BYTES : Nat = 512;
  transient let MAX_TITLE : Nat = 80;
  transient let MAX_HEIR_NAME : Nat = 60;
  transient let MAX_VAULTS_PER_OWNER : Nat = 10;
  transient let MAX_VAULTS : Nat = 5_000;
  transient let MAX_OPENS_PER_HEIR : Nat = 3;
  transient let MAX_OPENS_PER_VAULT : Nat = 10; // bounds the cycles one fee has to pay for
  transient let CYCLES_RESERVE : Nat = 300_000_000_000; // never let a derivation eat the freezing margin
  transient let MIN_ACTION_INTERVAL : Int = 3 * SEC;
  transient let CONTEXT : Blob = "piko-legacy-v1";

  // ---- Configuration (controllers only) ----

  var pikoLedgerId : Principal = Principal.fromText("56aad-fiaaa-aaaaj-qsefa-cai");
  var feeE8s : Nat = 100 * E8S;
  var feeRecipient : ?Principal = null; // null: this canister, then shared by distributeFees
  // Fees collected here are split equally between these accounts: the
  // PikoDice and PikoBlackjack bankrolls (a plain transfer to those canisters
  // is how their bankroll grows).
  var feeShareTargets : [Principal] = [
    Principal.fromText("7yyso-myaaa-aaaaj-qseia-cai"),
    Principal.fromText("d76up-oaaaa-aaaai-ax4ia-cai"),
  ];
  var sharedE8s : Nat = 0;
  var keyName : Text = "key_1"; // "dfx_test_key" on a local network
  var derivationCycles : Nat = 26_153_846_153; // vetkd_derive_key on key_1 (13-node subnet price list)
  var minIntervalSec : Nat = 7 * DAY_SEC;

  // ---- State ----

  let vaults = Map.empty<Nat, Vault>();
  let ibeIds = Map.empty<Blob, Nat>(); // every identity ever used, never reused
  var nextVaultId : Nat = 1;
  var cachedPublicKey : ?Blob = null;

  transient let lastAction = Map.empty<Principal, Int>();
  transient var distributing : Bool = false;
  transient let creating = Map.empty<Principal, Bool>();

  // ---- Helpers ----

  func isController(p : Principal) : Bool { Principal.isController(p) };

  func ledger() : Ledger { actor (Principal.toText(pikoLedgerId)) };

  func recipient() : Principal {
    switch feeRecipient { case (?p) p; case null Principal.fromActor(self) };
  };

  func keyId() : VetKdKeyId { { curve = #bls12_381_g2; name = keyName } };

  func throttle(p : Principal) : ?Text {
    let now = Time.now();
    switch (Map.get(lastAction, Principal.compare, p)) {
      case (?t) { if (now - t < MIN_ACTION_INTERVAL) { return ?"Slow down: one action every 3 seconds" } };
      case null {};
    };
    Map.add(lastAction, Principal.compare, p, now);
    null;
  };

  func deadline(v : Vault) : Int { v.lastCheckIn + v.intervalNs };
  func released(v : Vault, now : Int) : Bool { now >= deadline(v) };

  func ownerView(v : Vault, now : Int) : OwnerView {
    {
      id = v.id;
      title = v.title;
      createdAt = v.createdAt;
      lastCheckIn = v.lastCheckIn;
      intervalSec = Int.abs(v.intervalNs / SEC);
      deadline = deadline(v);
      released = released(v, now);
      heirs = Array.map<Heir, { name : Text; opens : Nat }>(v.heirs, func h = { name = h.name; opens = h.opens });
      secretBytes = v.ciphertext.size();
    };
  };

  func ownedVault(caller : Principal, id : Nat) : R<Vault> {
    switch (Map.get(vaults, Nat.compare, id)) {
      case (?v) { if (v.owner == caller) #ok v else #err "Not your vault" };
      case null #err "Unknown vault";
    };
  };

  /// Index of the heir whose claim hash matches SHA-256(proof), if any.
  func heirIndex(v : Vault, proof : Blob) : ?Nat {
    if (proof.size() != 32) { return null };
    let h = Sha256.fromBlob(proof);
    var i = 0;
    for (heir in v.heirs.vals()) {
      if (heir.claimHash == h) { return ?i };
      i += 1;
    };
    null;
  };

  func countOwned(p : Principal) : Nat {
    var n = 0;
    for (v in Map.values(vaults)) { if (v.owner == p) { n += 1 } };
    n;
  };

  func validate(a : CreateArgs) : ?Text {
    if (a.title.size() == 0 or a.title.size() > MAX_TITLE) { return ?"Name: 1 to 80 characters" };
    if (a.ibeId.size() != 32) { return ?"Bad vault identity" };
    if (Map.containsKey(ibeIds, Blob.compare, a.ibeId)) { return ?"Vault identity already used" };
    if (a.ciphertext.size() < 29) { return ?"Empty secret" };
    if (a.ciphertext.size() > MAX_SECRET_BYTES) { return ?"Secret too large (32 KB max)" };
    if (a.intervalSec < minIntervalSec or a.intervalSec > MAX_INTERVAL_SEC) {
      return ?("Check-in interval must be between " # Nat.toText(minIntervalSec) # " and " # Nat.toText(MAX_INTERVAL_SEC) # " seconds");
    };
    if (a.heirs.size() == 0 or a.heirs.size() > MAX_HEIRS) { return ?"1 to 5 heirs" };
    var i = 0;
    for (h in a.heirs.vals()) {
      if (h.name.size() == 0 or h.name.size() > MAX_HEIR_NAME) { return ?"Heir name: 1 to 60 characters" };
      if (h.claimHash.size() != 32) { return ?"Bad heir claim" };
      if (h.wrappedKey.size() == 0 or h.wrappedKey.size() > MAX_WRAPPED_BYTES) { return ?"Bad heir key" };
      var j = 0;
      for (o in a.heirs.vals()) {
        if (j < i and o.claimHash == h.claimHash) { return ?"Duplicate heir claim" };
        j += 1;
      };
      i += 1;
    };
    null;
  };

  // ---- Public reads ----

  public query func getConfig() : async Config {
    {
      feeE8s;
      ledger = pikoLedgerId;
      feeRecipient = recipient();
      feeShareTargets;
      sharedE8s;
      keyName;
      context = CONTEXT;
      minIntervalSec;
      maxIntervalSec = MAX_INTERVAL_SEC;
      maxHeirs = MAX_HEIRS;
      maxSecretBytes = MAX_SECRET_BYTES;
      maxVaultsPerOwner = MAX_VAULTS_PER_OWNER;
      maxOpensPerHeir = MAX_OPENS_PER_HEIR;
      vaultCount = Map.size(vaults);
    };
  };

  /// The vetKD public key for this canister and CONTEXT, once fetched.
  public query func getPublicKey() : async ?Blob { cachedPublicKey };

  /// Fetches (once) and returns the vetKD public key browsers encrypt to.
  public func fetchPublicKey() : async R<Blob> {
    switch cachedPublicKey { case (?k) { return #ok k }; case null {} };
    try {
      let r = await ic.vetkd_public_key({ canister_id = null; context = CONTEXT; key_id = keyId() });
      cachedPublicKey := ?r.public_key;
      #ok(r.public_key);
    } catch (e) { #err("vetKD public key unavailable: " # Error.message(e)) };
  };

  // ---- Owner ----

  public shared query ({ caller }) func myVaults() : async [OwnerView] {
    let now = Time.now();
    var out : [OwnerView] = [];
    for (v in Map.values(vaults)) {
      if (v.owner == caller) { out := Array.concat(out, [ownerView(v, now)]) };
    };
    out;
  };

  /// Pays the fee (ICRC-2: approve fee + ledger fee for this canister first),
  /// then stores the already-encrypted vault.
  public shared ({ caller }) func createVault(a : CreateArgs) : async R<Nat> {
    if (Principal.isAnonymous(caller)) { return #err "Log in first" };
    switch (throttle(caller)) { case (?e) { return #err e }; case null {} };
    if (Map.containsKey(creating, Principal.compare, caller)) { return #err "Another vault is being created" };
    if (Map.size(vaults) >= MAX_VAULTS) { return #err "No room for new vaults right now" };
    if (countOwned(caller) >= MAX_VAULTS_PER_OWNER) { return #err "You already have 10 vaults" };
    if (cachedPublicKey == null) { return #err "Encryption key not ready, reload the page" };
    switch (validate(a)) { case (?e) { return #err e }; case null {} };

    // Reserve the identity and the caller's slot across the ledger await.
    let id = nextVaultId;
    nextVaultId += 1;
    Map.add(ibeIds, Blob.compare, a.ibeId, id);
    Map.add(creating, Principal.compare, caller, true);
    let fee = feeE8s;
    if (fee > 0) {
      let res = try {
        await ledger().icrc2_transfer_from({
          spender_subaccount = null;
          from = { owner = caller; subaccount = null };
          to = { owner = recipient(); subaccount = null };
          amount = fee;
          fee = null;
          memo = ?Text.encodeUtf8("piko-legacy:vault:" # Nat.toText(id));
          created_at_time = null;
        });
      } catch (e) {
        Map.remove(ibeIds, Blob.compare, a.ibeId);
        Map.remove(creating, Principal.compare, caller);
        return #err("Ledger call failed: " # Error.message(e));
      };
      switch res {
        case (#Ok _) {};
        case (#Err e) {
          Map.remove(ibeIds, Blob.compare, a.ibeId);
          Map.remove(creating, Principal.compare, caller);
          return #err(
            switch e {
              case (#InsufficientFunds _) "Not enough PIKO in your wallet";
              case (#InsufficientAllowance _) "PIKO payment not approved";
              case _ "Payment refused by the ledger: " # debug_show e;
            }
          );
        };
      };
    };
    Map.remove(creating, Principal.compare, caller);
    let now = Time.now();
    Map.add(
      vaults,
      Nat.compare,
      id,
      {
        id;
        owner = caller;
        title = a.title;
        ibeId = a.ibeId;
        ciphertext = a.ciphertext;
        heirs = Array.map<HeirIn, Heir>(a.heirs, func h = { name = h.name; claimHash = h.claimHash; wrappedKey = h.wrappedKey; opens = 0 });
        createdAt = now;
        lastCheckIn = now;
        intervalNs = a.intervalSec * SEC;
        feePaidE8s = fee;
      },
    );
    if (fee > 0 and feeRecipient == null) {
      ignore Timer.setTimer<system>(#seconds 0, func() : async () { ignore await distribute() });
    };
    #ok id;
  };

  /// "I'm still here": restarts the countdown of every vault of the caller
  /// that is not released yet. Returns how many were reset.
  public shared ({ caller }) func checkIn() : async Nat {
    let now = Time.now();
    var n = 0;
    for (v in Map.values(vaults)) {
      if (v.owner == caller and not released(v, now)) {
        Map.add(vaults, Nat.compare, v.id, { v with lastCheckIn = now });
        n += 1;
      };
    };
    n;
  };

  /// Changes the check-in interval of a vault that is not released yet.
  /// Counts as a check-in.
  public shared ({ caller }) func setInterval(id : Nat, intervalSec : Nat) : async R<()> {
    let v = switch (ownedVault(caller, id)) { case (#ok v) v; case (#err e) { return #err e } };
    let now = Time.now();
    if (released(v, now)) { return #err "This vault is already released" };
    if (intervalSec < minIntervalSec or intervalSec > MAX_INTERVAL_SEC) { return #err "Interval out of range" };
    Map.add(vaults, Nat.compare, id, { v with lastCheckIn = now; intervalNs = intervalSec * SEC });
    #ok;
  };

  /// Erases a vault for good, released or not. Its identity is never reused.
  public shared ({ caller }) func deleteVault(id : Nat) : async R<()> {
    switch (ownedVault(caller, id)) { case (#err e) { return #err e }; case (#ok _) {} };
    Map.remove(vaults, Nat.compare, id);
    #ok;
  };

  // ---- Heirs (no login needed: the link is the credential) ----

  public query func heirLookup(id : Nat, proof : Blob) : async R<HeirView> {
    let v = switch (Map.get(vaults, Nat.compare, id)) { case (?v) v; case null { return #err "This vault does not exist (or was deleted)" } };
    let i = switch (heirIndex(v, proof)) { case (?i) i; case null { return #err "This link does not match the vault" } };
    let h = v.heirs[i];
    #ok {
      title = v.title;
      heirName = h.name;
      deadline = deadline(v);
      released = released(v, Time.now());
      opensLeft = if (h.opens >= MAX_OPENS_PER_HEIR) 0 else MAX_OPENS_PER_HEIR - h.opens;
    };
  };

  /// After release: returns the heir's encrypted material and the vault's
  /// vetKey, encrypted to the browser's one-time transport key.
  public shared func heirOpen(id : Nat, proof : Blob, transportPublicKey : Blob) : async R<Opened> {
    let v = switch (Map.get(vaults, Nat.compare, id)) { case (?v) v; case null { return #err "This vault does not exist (or was deleted)" } };
    let i = switch (heirIndex(v, proof)) { case (?i) i; case null { return #err "This link does not match the vault" } };
    if (not released(v, Time.now())) { return #err "Not released yet" };
    if (transportPublicKey.size() != 48) { return #err "Bad transport key" };
    if (v.heirs[i].opens >= MAX_OPENS_PER_HEIR) { return #err "This link has been opened too many times" };
    var vaultOpens = 0;
    for (h in v.heirs.vals()) { vaultOpens += h.opens };
    if (vaultOpens >= MAX_OPENS_PER_VAULT) { return #err "This vault has been opened too many times" };
    if (Cycles.balance() < derivationCycles + CYCLES_RESERVE) { return #err "The vault service is low on cycles, try again later" };

    // Count the open before the await so parallel calls cannot exceed the cap.
    func setOpens(delta : Int) {
      switch (Map.get(vaults, Nat.compare, id)) {
        case (?cur) {
          let hs = Array.tabulate<Heir>(cur.heirs.size(), func j {
            let h = cur.heirs[j];
            if (j == i) { { h with opens = Int.abs(h.opens + delta) } } else h;
          });
          Map.add(vaults, Nat.compare, id, { cur with heirs = hs });
        };
        case null {};
      };
    };
    setOpens(1);
    let r = try {
      await (with cycles = derivationCycles) ic.vetkd_derive_key({
        input = v.ibeId;
        context = CONTEXT;
        transport_public_key = transportPublicKey;
        key_id = keyId();
      });
    } catch (e) {
      setOpens(-1);
      return #err("Key derivation failed: " # Error.message(e));
    };
    #ok {
      ibeId = v.ibeId;
      ciphertext = v.ciphertext;
      wrappedKey = v.heirs[i].wrappedKey;
      encryptedVetKey = r.encrypted_key;
    };
  };

  // ---- Fee sharing ----

  /// Splits this canister's whole PIKO balance equally between
  /// feeShareTargets (each share minus one ledger fee). Vaults hold no PIKO,
  /// so everything on this account is collected fees.
  func distribute() : async R<Nat> {
    let n = feeShareTargets.size();
    if (n == 0) { return #ok 0 };
    if (distributing) { return #err "Already distributing" };
    distributing := true;
    let (balance, ledgerFee) = try {
      (await ledger().icrc1_balance_of({ owner = Principal.fromActor(self); subaccount = null }), await ledger().icrc1_fee());
    } catch (e) { distributing := false; return #err("Ledger unreachable: " # Error.message(e)) };
    let share = balance / n;
    if (share <= ledgerFee * 10) { distributing := false; return #ok 0 };
    var sent = 0;
    for (target in feeShareTargets.vals()) {
      let res = try {
        await ledger().icrc1_transfer({
          from_subaccount = null;
          to = { owner = target; subaccount = null };
          amount = share - ledgerFee : Nat;
          fee = ?ledgerFee;
          memo = ?Text.encodeUtf8("piko-legacy:share");
          created_at_time = null;
        });
      } catch (_) { #Err(#TemporarilyUnavailable) };
      switch res { case (#Ok _) { sent += share - ledgerFee : Nat }; case (#Err _) {} };
    };
    sharedE8s += sent;
    distributing := false;
    #ok sent;
  };

  /// Anyone may trigger it (e.g. if an automatic run failed).
  public func distributeFees() : async R<Nat> { await distribute() };

  // ---- Controllers ----

  public shared ({ caller }) func setFeeShareTargets(targets : [Principal]) : async R<()> {
    if (not isController(caller)) { return #err "Controller only" };
    if (targets.size() > 5) { return #err "5 targets max" };
    feeShareTargets := targets;
    #ok;
  };

  public shared ({ caller }) func setFee(e8s : Nat) : async R<()> {
    if (not isController(caller)) { return #err "Controller only" };
    if (e8s > HARD_MAX_FEE) { return #err "Fee above hard ceiling" };
    feeE8s := e8s;
    #ok;
  };

  public shared ({ caller }) func setFeeRecipient(p : ?Principal) : async R<()> {
    if (not isController(caller)) { return #err "Controller only" };
    feeRecipient := p;
    #ok;
  };

  public shared ({ caller }) func setPikoLedgerId(p : Principal) : async R<()> {
    if (not isController(caller)) { return #err "Controller only" };
    pikoLedgerId := p;
    #ok;
  };

  /// The key every existing vault was encrypted to: frozen once a vault exists.
  public shared ({ caller }) func setKeyName(name : Text) : async R<()> {
    if (not isController(caller)) { return #err "Controller only" };
    if (Map.size(ibeIds) > 0) { return #err "Vaults exist: the key can no longer change" };
    keyName := name;
    cachedPublicKey := null;
    #ok;
  };

  public shared ({ caller }) func setDerivationCycles(c : Nat) : async R<()> {
    if (not isController(caller)) { return #err "Controller only" };
    derivationCycles := c;
    #ok;
  };

  public shared ({ caller }) func setMinIntervalSec(s : Nat) : async R<()> {
    if (not isController(caller)) { return #err "Controller only" };
    if (s < HARD_MIN_INTERVAL_SEC) { return #err "Below hard minimum (60 s)" };
    minIntervalSec := s;
    #ok;
  };

  /// Sends fees collected on this canister's own account (only useful with no share targets).
  public shared ({ caller }) func withdrawFees(to : Principal, amountE8s : Nat) : async R<Nat> {
    if (not isController(caller)) { return #err "Controller only" };
    let res = try {
      await ledger().icrc1_transfer({
        from_subaccount = null;
        to = { owner = to; subaccount = null };
        amount = amountE8s;
        fee = null;
        memo = ?Text.encodeUtf8("piko-legacy:withdraw");
        created_at_time = null;
      });
    } catch (e) { return #err("Ledger call failed: " # Error.message(e)) };
    switch res { case (#Ok b) #ok b; case (#Err e) #err(debug_show e) };
  };
};
