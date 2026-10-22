export function HowItWorks() {
  return (
    <article className="prose-page">
      <h1>How it works</h1>

      <h3>What you do</h3>
      <ol>
        <li>Log in, write your secret (up to 32 KB of text) and give each heir a name.</li>
        <li>Choose how often you will check in: every month, 3 months, 6 months or year.</li>
        <li>You get one private link per heir. Send it to them however you like: on paper, by email, in a letter at your notary.</li>
        <li>Come back before the deadline and press <b>I'm still here</b>. One click resets all your vaults.</li>
      </ol>
      <p>
        If the deadline passes without a check-in, the vault is <b>released</b> for good. Each heir opens their link and reads
        the secret. No login needed.
      </p>

      <h3>Why nobody can read it early</h3>
      <p>Your secret is locked twice, in your browser, before it is sent:</p>
      <ul>
        <li>
          <b>Lock 1, the link.</b> Each heir's link holds a random key. It stays in the part of the link after <code>#</code>,
          which browsers never send to any server. Without the link, the secret cannot be read, even after release.
        </li>
        <li>
          <b>Lock 2, the network.</b> The second key is a <i>vetKey</i>, computed jointly by the nodes of the Internet
          Computer. No single node, and not us, ever holds it. The vault's public code asks the network for it only after the
          deadline has passed.
        </li>
      </ul>
      <p>
        So a heir holding the link early sees nothing, and someone who breaks into the service sees nothing either: they would
        still need the link.
      </p>

      <h3>Good to know</h3>
      <ul>
        <li>Links are shown once, when you create the vault. If you lose one, delete the vault and make a new one.</li>
        <li>There is no reminder email: put the deadline in your calendar.</li>
        <li>You can delete a vault at any time. Once released, a vault cannot be "un-released".</li>
        <li>Anyone holding a link can open it after release. Keep the links as safe as the secret itself.</li>
        <li>Each link can be opened 3 times. Copy the secret somewhere safe the first time.</li>
        <li>Creating a vault costs a one-time fee in PIKO. It goes straight to the house bankrolls of PikoDice and PikoBlackjack, half each.</li>
      </ul>
    </article>
  );
}
