import { useSession } from "../lib/session";

export function Home() {
  const { login } = useSession();
  return (
    <>
      <section className="hero">
        <p className="eyebrow">Dead man's switch</p>
        <h1>
          If something happens to you,
          <br />
          your secrets reach <em>the right people</em>.
        </h1>
        <p className="lead center">
          Write down what your family would need: seed phrases, passwords, where things are. Name who should get it. If you
          stop checking in, they can open it. Until then, nobody can. Not them, not us.
        </p>
        <ol className="how">
          <li>
            <b>1</b>Write your secret
          </li>
          <li>
            <b>2</b>Send each heir their link
          </li>
          <li>
            <b>3</b>Check in from time to time
          </li>
        </ol>
        <p className="cta">
          <button className="big-btn" onClick={login}>
            Create my vault
          </button>
        </p>
        <p className="muted small">Log in with Internet Identity. Your heirs don't need an account.</p>
      </section>

      <section className="facts">
        <div>
          <h3>Encrypted before it leaves your screen</h3>
          <p>Your text is locked in your browser. The service only ever stores scrambled bytes.</p>
        </div>
        <div>
          <h3>A link alone opens nothing</h3>
          <p>Before the deadline, the key that unlocks the vault does not exist yet. It is created by the Internet Computer network itself, only after you stop checking in.</p>
        </div>
        <div>
          <h3>Nothing worth stealing</h3>
          <p>The service only holds scrambled bytes. Even someone who broke into it would still need your heir's link.</p>
        </div>
      </section>
    </>
  );
}
