import { useCallback, useEffect, useMemo, useState } from "react";
import type { Identity } from "@icp-sdk/core/agent";
import { getLegacyActor } from "./lib/actors";
import { getStoredIdentity, login as iiLogin, logout as iiLogout } from "./lib/auth";
import { SessionContext, short, type Session } from "./lib/session";
import { Home } from "./pages/Home";
import { Vaults } from "./pages/Vaults";
import { NewVault } from "./pages/NewVault";
import { Open } from "./pages/Open";
import { HowItWorks } from "./pages/HowItWorks";
import { Wallet } from "./pages/Wallet";

function useRoute(): string[] {
  const read = () => window.location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const on = () => {
      setRoute(read());
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export default function App() {
  const route = useRoute();
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [toastMsg, setToastMsg] = useState<{ text: string; kind: "ok" | "err" } | null>(null);

  const actor = useMemo(() => getLegacyActor(identity ?? undefined), [identity]);
  const principal = identity ? identity.getPrincipal() : null;

  useEffect(() => {
    getStoredIdentity().then((id) => id && setIdentity(id));
  }, []);

  const toast = useCallback((text: string, kind: "ok" | "err" = "ok") => {
    setToastMsg({ text, kind });
    window.setTimeout(() => setToastMsg(null), 4500);
  }, []);

  const session: Session = {
    identity,
    principal,
    actor,
    toast,
    login: async () => {
      await iiLogin();
      setIdentity(await getStoredIdentity());
    },
    logout: async () => {
      await iiLogout();
      setIdentity(null);
      window.location.assign("#/");
    },
  };

  const [page, ...args] = route;
  let body;
  switch (page) {
    case "open":
      // Heir link: #/open/<vault id>/<secret>. The fragment never leaves the browser.
      body = <Open id={args[0] ?? ""} secret={args[1] ?? ""} />;
      break;
    case "new":
      body = <NewVault />;
      break;
    case "how":
      body = <HowItWorks />;
      break;
    case "wallet":
      body = <Wallet />;
      break;
    default:
      body = principal ? <Vaults /> : <Home />;
  }
  const isHeirPage = page === "open";

  return (
    <SessionContext.Provider value={session}>
      <div className="shell">
        <header className="top">
          <a className="brand" href="#/">
            <img src="/piko-logo.svg" alt="" />
            <span>
              PIKO <b>Legacy</b>
            </span>
          </a>
          <nav className="nav">
            {principal && !isHeirPage && <a href="#/">My vaults</a>}
            {principal && !isHeirPage && (
              <a href="#/wallet" className={page === "wallet" ? "on" : ""}>
                Wallet
              </a>
            )}
            <a href="#/how" className={page === "how" ? "on" : ""}>
              How it works
            </a>
          </nav>
          {!isHeirPage && (
            <div className="account">
              {principal ? (
                <>
                  <a className="account-id" href="#/wallet" title={`${principal.toText()} (open wallet)`}>
                    <code>{short(principal)}</code>
                  </a>
                  <button className="ghost" onClick={session.logout}>
                    Log out
                  </button>
                </>
              ) : (
                <button onClick={session.login}>Log in</button>
              )}
            </div>
          )}
        </header>

        <main>{body}</main>

        <footer className="foot">
          <a href="#/how">How it works</a>
          <span>Encrypted in your browser · keys by the Internet Computer (vetKeys)</span>
          <a href="https://www.piko.network/">piko.network</a>
        </footer>
      </div>
      {toastMsg && <div className={`toast ${toastMsg.kind}`}>{toastMsg.text}</div>}
    </SessionContext.Provider>
  );
}
