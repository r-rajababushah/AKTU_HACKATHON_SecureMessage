import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

const api = async (route, body) => {
  const response = await fetch(route, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
};

function App() {
  const [state, setState] = useState({ keys_ready: false, session_ready: false, processed_count: 0, messages: [] });
  const [packages, setPackages] = useState([]);
  const [sender, setSender] = useState("Alice");
  const [message, setMessage] = useState("Meeting deadline is Friday.");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [received, setReceived] = useState(null);
  const [viewEnvelope, setViewEnvelope] = useState(null);
  const [demo, setDemo] = useState(null);
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    try {
      const [nextState, nextPackages] = await Promise.all([api("/api/state"), api("/api/packages")]);
      setState(nextState); setPackages(nextPackages.packages);
    } catch (problem) { setError(problem.message); }
  };
  useEffect(() => { refresh(); }, []);

  const act = async (fn) => {
    setBusy(true); setError(""); setNotice(""); setDemo(null); setReceived(null);
    try { const result = await fn(); if (result?.message) setNotice(result.message); await refresh(); return result; }
    catch (problem) { setError(problem.message); }
    finally { setBusy(false); }
  };
  const generate = () => act(() => api("/api/keys", {}));
  const exchange = () => act(() => api("/api/exchange", {}));
  const send = () => act(async () => {
    const result = await api("/api/send", { sender, message });
    setNotice(result.message); return result;
  });
  const receive = (file) => act(async () => {
    const result = await api("/api/receive", { file }); setReceived(result);
    setNotice(result.decrypted ? "All checks passed. Plaintext is safe to display." : "Message rejected."); return {};
  });
  const inspectEnvelope = async (file) => {
    setError(""); setViewEnvelope(null);
    try { const result = await api(`/api/package?file=${encodeURIComponent(file)}`); setViewEnvelope(result.package); }
    catch (problem) { setError(problem.message); }
  };

  return <div className="shell">
    <header className="topbar"><div className="brand"><span className="brand-mark">S</span><div><b>SecureMessage</b><small>TEAM 3 · CRUSADERS</small></div></div><div className="local-pill"><i/> LOCAL DEMO <span>·</span> NO NETWORK CHAT</div></header>
    <main>
      <section className="hero"><div className="hero-copy"><div className="eyebrow">BUILD IT SECURE · CRYPTOGRAPHY SHOWCASE</div><h1>Private messages.<br/><em>Verifiable senders.</em></h1><p>See how Alice and Bob establish shared keys, protect a message, and reject tampering before plaintext appears.</p></div><div className="hero-seal"><div className="seal-ring"><span>🔒</span></div><small>CRYPTOGRAPHIC<br/>PROOF, LIVE</small></div></section>

      <section className="status-grid" aria-label="Session status">
        <Status label="PARTICIPANT KEYS" value={state.keys_ready ? "READY" : "NOT CREATED"} okay={state.keys_ready} detail="X25519 + Ed25519" />
        <Status label="SHARED SESSION" value={state.session_ready ? "ESTABLISHED" : "NOT ESTABLISHED"} okay={state.session_ready} detail="HKDF · AES + HMAC keys" />
        <Status label="MESSAGES ACCEPTED" value={String(state.processed_count).padStart(2, "0")} okay={state.processed_count > 0} detail="Replay IDs remembered this run" />
      </section>

      {(notice || error) && <div className={`notice ${error ? "notice-error" : "notice-good"}`} role="status">{error || notice}<button onClick={() => { setNotice(""); setError(""); }}>×</button></div>}

      <div className="main-grid">
        <section className="panel setup-panel"><div className="panel-heading"><div><span className="step">01 — 02</span><h2>Establish trust & keys</h2></div><span className="icon-chip">⌘</span></div>
          <div className="step-row"><span className={`step-dot ${state.keys_ready ? "done" : ""}`}>{state.keys_ready ? "✓" : "1"}</span><div className="step-copy"><b>Create Alice & Bob's key pairs</b><p>Private keys stay in local files and are never shown.</p></div><button className="button button-secondary" onClick={generate} disabled={busy || state.keys_ready}>{state.keys_ready ? "Generated" : "Generate keys"}</button></div>
          <div className="step-row"><span className={`step-dot ${state.session_ready ? "done" : ""}`}>{state.session_ready ? "✓" : "2"}</span><div className="step-copy"><b>Exchange public keys</b><p>Both sides derive the same secret; HKDF creates two purpose-specific keys.</p></div><button className="button button-primary" onClick={exchange} disabled={busy || !state.keys_ready || state.session_ready}>{state.session_ready ? "Connected" : "Exchange keys"}</button></div>
          <div className="trust-note"><span>ⓘ</span><p>Signing identity is only meaningful when the public signing key is trusted. This single-computer demo trusts the keys it generated.</p></div>
        </section>

        <section className="panel compose-panel"><div className="panel-heading"><div><span className="step">03 — 04</span><h2>Compose a secure message</h2></div><span className="icon-chip">✉</span></div>
          <label className="field-label" htmlFor="sender">SENDER</label><div className="sender-toggle"><button className={sender === "Alice" ? "selected" : ""} onClick={() => setSender("Alice")}>Alice <span>→ Bob</span></button><button className={sender === "Bob" ? "selected" : ""} onClick={() => setSender("Bob")}>Bob <span>→ Alice</span></button></div>
          <label className="field-label" htmlFor="message">MESSAGE CONTENT</label><textarea id="message" rows="3" value={message} onChange={(event) => setMessage(event.target.value)} placeholder="Type a message..." />
          <button className="button button-primary send-button" onClick={send} disabled={busy || !state.session_ready || !message.trim()}>Encrypt, sign & send <span>↗</span></button>
          <div className="send-foot"><span>◉ AES-256-GCM</span><span>◉ Ed25519 signature</span><span>◉ HMAC-SHA256</span></div>
        </section>

        <section className="panel inbox-panel"><div className="panel-heading"><div><span className="step">05</span><h2>Verify & receive</h2></div><span className="icon-chip">✓</span></div>
          {packages.length === 0 ? <div className="empty-state"><span>▤</span><b>Your message packages appear here</b><p>Send a message to create an encrypted package.</p></div> : <div className="package-list">{packages.map((item) => <article className="package-row" key={item.file}><div className="package-icon">▣</div><div className="package-info"><b>{item.sender} <span>→</span> {item.recipient}</b><small>{new Date(item.created_at).toLocaleString()}</small><code>{item.message_id.slice(0, 18)}…</code></div><div className="package-actions"><button className="button button-inspect" onClick={() => inspectEnvelope(item.file)}>Inspect package</button><button className="button button-verify" onClick={() => receive(item.file)} disabled={busy}>Verify & decrypt</button></div></article>)}</div>}
          {viewEnvelope && <div className="envelope-view"><div><b>INTERCEPTED ENVELOPE · PLAINTEXT IS ABSENT</b><button onClick={() => setViewEnvelope(null)} aria-label="Close package">×</button></div><p>A passive observer can see these package fields. The ciphertext is encrypted with AES-GCM; Base64 only makes binary bytes printable.</p><pre>{JSON.stringify(viewEnvelope, null, 2)}</pre></div>}
          {received && received.decrypted && <div className="received-box"><div className="checkline"><b>✓ SIGNATURE VERIFIED</b><b>✓ HMAC VERIFIED</b></div><span>DECRYPTED MESSAGE</span><p>{received.plaintext}</p></div>}
          {received && !received.decrypted && <div className="received-box rejected"><b>MESSAGE REJECTED</b><span>Signature: {received.signature ? "valid" : "failed"} · HMAC: {received.hmac ? "valid" : "failed"}</span></div>}
        </section>
      </div>

      <section className="proof-section"><div className="proof-title"><div><div className="eyebrow">JUDGE-READY PROOFS</div><h2>See the protections fail safely</h2></div><p>Each demo performs real cryptographic operations on a temporary message.</p></div><div className="proof-grid">
        <ProofCard number="01" title="Tampering detection" copy="Flip a ciphertext bit. Signature and HMAC verification fail; plaintext is rejected. The original package is checked afterward." button="Run tampering demo" onClick={() => act(async () => { const result = await api("/api/tamper-demo", {}); setDemo({ kind: "tamper", ...result }); setNotice(result.message); return {}; })} disabled={busy || !state.session_ready} />
        <ProofCard number="02" title="Signature forgery" copy="Sign Alice's envelope with Bob's private key, then verify against Alice's trusted public key. Verification fails." button="Run forgery demo" onClick={() => act(async () => { const result = await api("/api/forgery-demo", {}); setDemo({ kind: "forgery", ...result }); setNotice(result.message); return {}; })} disabled={busy || !state.session_ready} />
      </div>{demo && <div className={`demo-result ${demo.tamper_detected || demo.rejected ? "result-good" : "result-bad"}`}><b>{demo.tamper_detected || demo.rejected ? "✓ ATTACK REJECTED" : "! CHECK FAILED"}</b><div>{demo.kind === "tamper" ? <>Signature {demo.signature ? "valid" : "failed"} · HMAC {demo.hmac ? "valid" : "failed"} · Modified copy rejected {demo.modified_rejected ? "✓" : "✕"} · Original package {demo.original_valid ? "valid ✓" : "invalid ✕"}</> : <>Alice signature verification {demo.signature ? "passed" : "failed ✓"} · Plaintext displayed {demo.plaintext_shown ? "yes" : "no ✓"}</>}</div></div>}</section>

      <section className="flow-strip"><div><span>01</span><b>X25519</b><small>Agree on a secret</small></div><i>→</i><div><span>02</span><b>HKDF</b><small>Derive separate keys</small></div><i>→</i><div><span>03</span><b>AES-GCM</b><small>Encrypt the message</small></div><i>→</i><div><span>04</span><b>Ed25519 + HMAC</b><small>Prove & verify</small></div></section>
    </main><footer><span>SecureMessage · Team 3 — Crusaders</span><span>LOCAL EDUCATIONAL PROTOTYPE · NOT A NETWORK CHAT APP</span></footer>
  </div>;
}

function Status({ label, value, detail, okay }) { return <article className="status-card"><span className="status-label">{label}</span><b className={okay ? "is-ready" : ""}><i className={okay ? "ready-dot" : "idle-dot"}/>{value}</b><small>{detail}</small></article>; }
function ProofCard({ number, title, copy, button, onClick, disabled }) { return <article className="proof-card"><span className="proof-number">{number} / CRYPTO DEMO</span><h3>{title}</h3><p>{copy}</p><button className="button button-outline" onClick={onClick} disabled={disabled}>{button}<span>↗</span></button></article>; }

createRoot(document.getElementById("root")).render(<App />);
