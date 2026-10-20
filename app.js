/* ============================================================================
   Secure Chat Lab — Application Logic
   ============================================================================
   Controls the UI, wires up events, drives the animated key exchange,
   manages chat messaging with encryption, and simulates attacks.
   -------------------------------------------------------------------------- */

// ============================================================================
// State
// ============================================================================

let alice = null;
let bob = null;
let eveA = null;   // Eve's identity pretending to be Bob (talks to Alice)
let eveB = null;   // Eve's identity pretending to be Alice (talks to Bob)
let mitmActive = false;
let ready = false;
let lastPacket = null;   // { receiver: Keys, chatEl: Element, packet: Uint8Array }

// ============================================================================
// DOM References
// ============================================================================

const $  = id => document.getElementById(id);
const el = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html) e.innerHTML = html;
  return e;
};

const aliceMessages = $("alice-messages");
const bobMessages   = $("bob-messages");
const eveMessages   = $("eve-messages");
const keyLog        = $("key-log");
const aliceInput    = $("alice-input");
const bobInput      = $("bob-input");
const aliceSend     = $("alice-send");
const bobSend       = $("bob-send");
const btnReplay     = $("btn-replay");
const btnKX         = $("btn-key-exchange");
const chkTamper     = $("chk-tamper");
const chkMitm       = $("chk-mitm");
const statusBadge   = $("status-badge");
const statusText    = $("status-text");
const aliceIndicator = $("alice-indicator");
const bobIndicator   = $("bob-indicator");

// ============================================================================
// Input Event Listeners
// ============================================================================

aliceInput.addEventListener("keydown", e => { if (e.key === "Enter") sendAlice(); });
bobInput.addEventListener("keydown", e => { if (e.key === "Enter") sendBob(); });

// ============================================================================
// UI Helpers
// ============================================================================

function setInputsEnabled(on) {
  aliceInput.disabled = !on;
  bobInput.disabled = !on;
  aliceSend.disabled = !on;
  bobSend.disabled = !on;
  btnReplay.disabled = !on;
}

function setStatus(text, type) {
  statusText.textContent = text;
  statusBadge.className = "status-badge status-" + type;
}

function scrollToBottom(container) {
  requestAnimationFrame(() => {
    container.scrollTop = container.scrollHeight;
  });
}

function appendChat(container, className, html) {
  const msg = el("div", className, html);
  container.appendChild(msg);
  scrollToBottom(container);
  return msg;
}

function appendEveLog(headerHtml, fields, noteHtml, noteClass) {
  const msgDiv = el("div", "eve-msg");

  if (headerHtml) {
    const hdr = el("div", "eve-msg-header", headerHtml);
    msgDiv.appendChild(hdr);
  }

  if (fields) {
    fields.forEach(([label, value]) => {
      const row = el("div", "eve-msg-field",
        `<span class="eve-field-label">${label}:</span><span class="eve-field-value">${value}</span>`
      );
      msgDiv.appendChild(row);
    });
  }

  if (noteHtml) {
    const note = el("div", `eve-msg-note ${noteClass || ""}`, noteHtml);
    msgDiv.appendChild(note);
  }

  eveMessages.appendChild(msgDiv);
  scrollToBottom(eveMessages);
}

function clearKeyLog() {
  keyLog.innerHTML = "";
}

function logKey(html, cls = "kl-info") {
  const line = el("span", `${cls} kx-animate`, html);
  keyLog.appendChild(line);
  keyLog.scrollTop = keyLog.scrollHeight;
}

function timeNow() {
  return new Date().toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// ============================================================================
// Key Exchange (animated, step by step)
// ============================================================================

async function startKeyExchange() {
  resetAll(true);
  btnKX.disabled = true;
  mitmActive = chkMitm.checked;
  clearKeyLog();

  // Create parties
  alice = new Party("Alice");
  bob = new Party("Bob");
  await alice.generateKeys();
  await bob.generateKeys();

  if (mitmActive) {
    eveA = new Party("Eve-as-Bob");
    eveB = new Party("Eve-as-Alice");
    await eveA.generateKeys();
    await eveB.generateKeys();
  }

  // Step 1
  await delay(100);
  kxStep1();

  // Step 2
  await delay(800);
  kxStep2();

  // Step 3
  await delay(800);
  kxStep3();

  // Step 4
  await delay(800);
  await kxStep4();

  // Step 5
  await delay(700);
  kxStep5();

  btnKX.disabled = false;
}

function kxStep1() {
  logKey("STEP 1 &nbsp; Public parameters (known to everyone, including Eve)", "kl-step");
  logKey(`p = ${shortHex(P_HEX)} &nbsp; <span class="kl-value">(2048-bit safe prime, RFC 3526)</span>`);
  logKey("g = 2");
}

function kxStep2() {
  logKey("STEP 2 &nbsp; Each side picks a SECRET number and computes a PUBLIC value (g<sup>x</sup> mod p)", "kl-step");
  logKey(`Alice secret a = ${shortHex(alice.secretHex)} &nbsp; <span class="kl-value">(never sent)</span>`);
  logKey(`Alice public A = ${shortHex(alice.publicHex)}`);
  logKey(`Bob &nbsp; secret b = ${shortHex(bob.secretHex)} &nbsp; <span class="kl-value">(never sent)</span>`);
  logKey(`Bob &nbsp; public B = ${shortHex(bob.publicHex)}`);
}

function kxStep3() {
  logKey("STEP 3 &nbsp; Public values are sent over the open network", "kl-step");

  if (mitmActive) {
    logKey("⚠ Eve intercepts both values and substitutes her own!", "kl-bad");
    logKey(`Alice receives (thinks it's Bob's): ${shortHex(eveA.publicHex)}`, "kl-bad");
    logKey(`Bob &nbsp; receives (thinks it's Alice's): ${shortHex(eveB.publicHex)}`, "kl-bad");
  } else {
    logKey("Alice → Bob : A &nbsp;&nbsp;&nbsp; Bob → Alice : B");
    logKey("Eve sees A and B, but cannot derive a or b &nbsp; (discrete logarithm problem)");
  }

  // Eve's panel: show intercepted public values
  appendEveLog(
    `<span class="eve-msg-time">${timeNow()}</span><span class="eve-msg-direction">🔑 Key Exchange Observed</span>`,
    [
      ["A", shortHex(alice.publicHex, 20)],
      ["B", shortHex(bob.publicHex, 20)],
    ],
    mitmActive ? "Eve intercepts and replaces both values!" : "Eve cannot compute the shared secret.",
    mitmActive ? "eve-note-attack" : "eve-note-nokey"
  );
}

async function kxStep4() {
  logKey("STEP 4 &nbsp; Compute shared secret → derive keys with HKDF-SHA256", "kl-step");

  if (mitmActive) {
    // Eve intercepts: Alice ↔ Eve, Bob ↔ Eve
    const sA = await alice.computeShared(eveA.rawPublicKey);
    const sB = await bob.computeShared(eveB.rawPublicKey);
    await eveA.computeShared(alice.rawPublicKey);  // Eve ↔ Alice
    await eveB.computeShared(bob.rawPublicKey);    // Eve ↔ Bob

    logKey(`Alice secret = ${shortHex(bytesToHex(sA))}`);
    logKey(`Bob &nbsp; secret = ${shortHex(bytesToHex(sB))}`);
    logKey("→ Alice and Bob have DIFFERENT secrets; each shares a key with Eve.", "kl-bad");
  } else {
    // Normal: Alice ↔ Bob
    const sA = await alice.computeShared(bob.rawPublicKey);
    const sB = await bob.computeShared(alice.rawPublicKey);

    logKey(`Alice computes B<sup>a</sup> mod p = ${shortHex(bytesToHex(sA))}`);
    logKey(`Bob &nbsp; computes A<sup>b</sup> mod p = ${shortHex(bytesToHex(sB))}`);
    logKey("→ Identical shared secret on both sides ✓", "kl-ok");
  }

  logKey(`AES-256 key &nbsp;(Alice) = ${bytesToHex(alice.keys.aesKeyRaw).slice(0, 32)}…`);
  logKey(`HMAC-SHA256 key (Alice) = ${bytesToHex(alice.keys.macKeyRaw).slice(0, 32)}…`);
}

function kxStep5() {
  ready = true;
  setInputsEnabled(true);
  aliceIndicator.classList.add("active");
  bobIndicator.classList.add("active");

  if (mitmActive) {
    setStatus("COMPROMISED (MITM)", "compromised");
    logKey("DONE &nbsp; Channel appears secure to Alice and Bob, but Eve reads everything.", "kl-bad");
    logKey("Fix: authenticate the public values with RSA signatures or certificates (as in TLS).", "kl-bad");
  } else {
    setStatus("SECURE CHANNEL", "secure");
    logKey("DONE &nbsp; Secure channel established. Try sending messages!", "kl-ok");
  }

  appendChat(aliceMessages, "msg msg-sys", "🔒 Channel ready — start chatting");
  appendChat(bobMessages, "msg msg-sys", "🔒 Channel ready — start chatting");
}

// ============================================================================
// Messaging
// ============================================================================

function sendAlice() {
  if (!ready) return;
  const text = aliceInput.value.trim();
  if (!text) return;
  aliceInput.value = "";
  doSend(alice, bob, aliceMessages, bobMessages, eveA, "Alice", text);
}

function sendBob() {
  if (!ready) return;
  const text = bobInput.value.trim();
  if (!text) return;
  bobInput.value = "";
  doSend(bob, alice, bobMessages, aliceMessages, eveB, "Bob", text);
}

async function doSend(sender, receiver, myChat, theirChat, eveIdent, senderName, text) {
  // Show in sender's panel
  appendChat(myChat, "msg msg-me", escapeHtml(text));

  // Encrypt
  let packet = await encryptMessage(sender.keys, text);

  // Log in Eve's panel
  const parsed = parsePacket(packet);
  const receiverName = senderName === "Alice" ? "Bob" : "Alice";
  appendEveLog(
    `<span class="eve-msg-time">${timeNow()}</span><span class="eve-msg-direction">${senderName} → ${receiverName}</span>`,
    [
      ["seq", parsed.seq],
      ["IV", shortHex(parsed.iv, 16)],
      ["data", shortHex(parsed.ct, 24)],
      ["HMAC", shortHex(parsed.tag, 16)],
    ],
    null, null
  );

  if (mitmActive && eveIdent) {
    // Eve decrypts with her key for this sender
    try {
      const plaintext = await decryptMessage(eveIdent.keys, packet, false);
      appendEveLog(null, null,
        `🔓 DECRYPTED: "${escapeHtml(plaintext)}"`, "eve-note-decrypted"
      );

      // Re-encrypt with Eve's key for the other party
      let forwardText = plaintext;
      const otherEve = (eveIdent === eveA) ? eveB : eveA;

      if (chkTamper.checked) {
        forwardText += " [edited by Eve]";
        chkTamper.checked = false;
        appendEveLog(null, null,
          "✏️ Eve modifies the message before forwarding!", "eve-note-attack"
        );
      }

      packet = await encryptMessage(otherEve.keys, forwardText);
    } catch (e) {
      appendEveLog(null, null, `Error: ${e.message}`, "eve-note-attack");
    }
  } else {
    appendEveLog(null, null, "🔐 Eve cannot read this (no key)", "eve-note-nokey");

    if (chkTamper.checked) {
      packet = tamperPacket(packet);
      chkTamper.checked = false;
      appendEveLog(null, null,
        "⚡ Eve FLIPS ONE BIT of the ciphertext!", "eve-note-attack"
      );
    }
  }

  // Deliver to receiver
  await deliverMessage(receiver, theirChat, packet);
}

async function deliverMessage(receiver, chat, packet) {
  try {
    const text = await decryptMessage(receiver.keys, packet);
    appendChat(chat, "msg msg-them", escapeHtml(text));
    appendChat(chat, "msg-verified",
      `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> HMAC verified`
    );
    lastPacket = { receiver, chat, packet: new Uint8Array(packet) };
  } catch (e) {
    appendChat(chat, "msg-rejected",
      `⛔ REJECTED: ${escapeHtml(e.message)}`
    );
    appendEveLog(null, null,
      `Receiver rejected: ${escapeHtml(e.message)}`, "eve-note-ok"
    );
  }
}

// ============================================================================
// Replay Attack
// ============================================================================

async function replayAttack() {
  if (!lastPacket) return;

  appendEveLog(
    `<span class="eve-msg-time">${timeNow()}</span><span class="eve-msg-direction">🔄 REPLAY ATTACK</span>`,
    null,
    "Eve re-sends a previously captured packet", "eve-note-attack"
  );

  await deliverMessage(lastPacket.receiver, lastPacket.chat, lastPacket.packet);
}

// ============================================================================
// Reset
// ============================================================================

function resetAll(silent = false) {
  ready = false;
  alice = bob = eveA = eveB = null;
  lastPacket = null;
  mitmActive = false;
  chkTamper.checked = false;

  aliceMessages.innerHTML = "";
  bobMessages.innerHTML = "";
  eveMessages.innerHTML = "";

  setInputsEnabled(false);
  setStatus("NOT SECURED", "insecure");

  aliceIndicator.classList.remove("active");
  bobIndicator.classList.remove("active");

  btnKX.disabled = false;

  if (!silent) {
    clearKeyLog();
    keyLog.innerHTML = `
      <div class="key-welcome">
        <div class="key-welcome-icon">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
          </svg>
        </div>
        <p>Click <strong>"Run Key Exchange"</strong> to start the Diffie-Hellman protocol.</p>
        <p class="key-welcome-tip">💡 Tip: Enable <em>"Man-in-the-Middle"</em> before running the exchange to see why unauthenticated DH is vulnerable.</p>
      </div>`;
  }
}

// ============================================================================
// Toggle Key Panel
// ============================================================================

function toggleKeyPanel() {
  const body = $("key-body");
  const btn = $("btn-collapse");
  body.classList.toggle("collapsed");
  btn.classList.toggle("collapsed");
}

// ============================================================================
// Utilities
// ============================================================================

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
