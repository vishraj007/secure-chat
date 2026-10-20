import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak, Preformatted, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        if self._pageNumber > 1:
            self.saveState()
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            # Running Header
            self.drawString(46, self._pagesize[1] - 34, "Secure Chat Application (ICS412) — Project Report")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(46, self._pagesize[1] - 38, self._pagesize[0] - 46, self._pagesize[1] - 38)
            # Running Footer
            self.line(46, 38, self._pagesize[0] - 46, 38)
            page_str = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(self._pagesize[0] - 46, 26, page_str)
            self.drawString(46, 26, "Vishal Rawat (2023BCS0101)  |  Jatin Nath (2023BCD0014)  |  Rishi (2023BCD0023)")
            self.restoreState()

def build_pdf(filename="PROJECT_REPORT.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=46,
        rightMargin=46,
        topMargin=50,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    title_cover = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=26,
        leading=32,
        textColor=colors.HexColor("#1e3a8a"),
        spaceAfter=15
    )

    meta_style = ParagraphStyle(
        'CoverMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=18,
        textColor=colors.HexColor("#334155")
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11.5,
        leading=15,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.2,
        leading=14,
        textColor=colors.HexColor("#1f2937"),
        spaceAfter=5,
        alignment=4 # Justify
    )

    bullet_style = ParagraphStyle(
        'BulletText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.8,
        leading=13,
        textColor=colors.HexColor("#1f2937"),
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=2.5
    )

    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.8,
        leading=10.5,
        textColor=colors.HexColor("#1e293b")
    )

    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.2,
        leading=11,
        textColor=colors.white
    )

    caption_style = ParagraphStyle(
        'FigCaption',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#475569"),
        alignment=1, # Center
        spaceAfter=12
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.2,
        leading=9.5,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # ==========================================
    # COVER BLOCK (Matching template)
    # ==========================================
    story.append(Paragraph("Title of the Project", ParagraphStyle('Sub', fontName='Helvetica-Bold', fontSize=12, textColor=colors.HexColor("#64748b"))))
    story.append(Paragraph("Secure Chat Application using Diffie-Hellman + AES + HMAC", title_cover))
    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>Course Name:</b> Cryptography and Network Security (ICS412)", meta_style))
    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>Student Name:</b>", meta_style))
    story.append(Paragraph("• <b>Vishal Rawat</b> &nbsp;(Roll No: 2023BCS0101)", meta_style))
    story.append(Paragraph("• <b>Jatin Nath</b> &nbsp;&nbsp;&nbsp;(Roll No: 2023BCD0014)", meta_style))
    story.append(Paragraph("• <b>Rishi</b> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(Roll No: 2023BCD0023)", meta_style))
    
    # Large spacing matching template requirements
    story.append(Spacer(1, 150))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=20))
    story.append(PageBreak())

    # ==========================================
    # SECTION 1: TITLE OF THE PROJECT
    # ==========================================
    story.append(Paragraph("Title of the Project", h1_style))
    story.append(Paragraph(
        "<b>Secure Chat Application using Diffie-Hellman Key Exchange, AES-256-CBC, and HMAC-SHA256 with Real-Time Attack Simulation</b>",
        ParagraphStyle('MainProjTitle', fontName='Helvetica-Bold', fontSize=13, leading=16, textColor=colors.HexColor("#1e3a8a"), spaceAfter=10)
    ))

    # ==========================================
    # SECTION 2: ABSTRACT
    # ==========================================
    story.append(Paragraph("Abstract", h1_style))
    story.append(Paragraph(
        "In contemporary computer networks, public communication channels are fundamentally untrusted and susceptible to interception, manipulation, and spoofing. This project presents the design, mathematical formalization, and interactive implementation of an end-to-end secure communication system modeling modern transport layer security (TLS 1.3 / Signal Protocol architectures). The system integrates four foundational pillars of modern applied cryptography:",
        body
    ))
    story.append(Paragraph("• <b>Asymmetric Key Exchange:</b> Diffie-Hellman protocol based on RFC 3526 2048-bit MODP safe prime groups (p, g) to establish a shared master secret over an insecure channel without transmitting private parameters.", bullet_style))
    story.append(Paragraph("• <b>Key Derivation Function (KDF):</b> HMAC-based Extract-and-Expand Key Derivation Function (HKDF-SHA256, RFC 5869) to derive independent, cryptographically strong 256-bit symmetric encryption keys (K<sub>AES</sub>) and message authentication keys (K<sub>HMAC</sub>).", bullet_style))
    story.append(Paragraph("• <b>Symmetric Payload Confidentiality:</b> Advanced Encryption Standard (AES-256) operating in Cipher Block Chaining (CBC) mode with cryptographically secure random Initialization Vectors (IV, 128-bit) per message and PKCS#7 padding.", bullet_style))
    story.append(Paragraph("• <b>Message Integrity, Authentication, and Anti-Replay Defense:</b> Encrypt-then-MAC paradigm utilizing HMAC-SHA256 computed over the 64-bit monotonically increasing sequence number, IV, and ciphertext payload (Seq || IV || C).", bullet_style))
    story.append(Paragraph(
        "To provide rigorous educational insight and empirical evaluation, the application embeds a real-time, tri-party visual environment containing Alice (sender), Bob (receiver), and Eve (network adversary). Through this platform, four critical adversarial scenarios are demonstrated: passive eavesdropping, ciphertext tampering (single-bit flipping), packet replay attacks, and unauthenticated Diffie-Hellman Man-in-the-Middle (MITM) interception. The implementation has been validated both as a standalone Python application leveraging the Python cryptography library and as a zero-dependency web interface utilizing the W3C Web Cryptography API.",
        body
    ))

    # ==========================================
    # SECTION 3: INTRODUCTION
    # ==========================================
    story.append(Paragraph("Introduction", h1_style))
    story.append(Paragraph("<b>1. Motivation and Problem Context</b>", h2_style))
    story.append(Paragraph(
        "The rapid proliferation of networked applications, distributed databases, and real-time messaging services has elevated information security from an operational feature to a critical requirement. Open packet-switched networks inherently expose packets to inspection and unauthorized transformation by intermediate entities, including untrusted routers, ISP wiretapping, and active adversaries. Achieving secure communication over an untrusted transmission medium necessitates fulfilling four fundamental security objectives defined by the CIA triad: <b>Confidentiality</b>, <b>Integrity</b>, <b>Authenticity</b>, and <b>Freshness / Anti-Replay Protection</b>.",
        body
    ))
    story.append(Paragraph("<b>2. The Cryptographic Dilemma</b>", h2_style))
    story.append(Paragraph(
        "Symmetric ciphers such as AES-256 provide high-throughput, computationally lightweight encryption suitable for bulk data transfer. However, symmetric ciphers suffer from the fundamental <i>Key Distribution Problem</i>: two parties wishing to communicate must securely share a secret key beforehand. Transmitting the key across the open channel nullifies confidentiality. Conversely, asymmetric algorithms solve key distribution through mathematically related key pairs but incur substantial computational overhead, rendering them impractical for streaming message encryption.",
        body
    ))
    story.append(Paragraph("<b>3. Proposed Solution</b>", h2_style))
    story.append(Paragraph(
        "This project synthesizes asymmetric and symmetric paradigms into a <b>hybrid cryptographic architecture</b>: ephemeral Diffie-Hellman establishes the shared master secret; HKDF-SHA256 stretches and separates the shared entropy into dedicated operational keys; AES-256-CBC secures arbitrary-length plaintexts; and HMAC-SHA256 binds message integrity and sequence counter tracking to the derived MAC key. Furthermore, Eve's adversarial tap provides real-time visibility into raw network packets, verifying that an adversary observes only pseudo-random bitstrings while demonstrating failure modes when packets are corrupted or replayed.",
        body
    ))

    # ==========================================
    # SECTION 4: METHODOLOGY
    # ==========================================
    story.append(Paragraph("Methodology", h1_style))
    story.append(Paragraph("<b>1. System Architecture & Threat Model</b>", h2_style))
    story.append(Paragraph(
        "The system architecture models two communicating endpoints (Alice and Bob) communicating over a shared, untrusted network wire observed and manipulated by an adversary (Eve). Under the standard Dolev-Yao threat model, Eve has the capabilities of passive eavesdropping, active message modification (bit-flipping), message replay, and unauthenticated Man-in-the-Middle (MITM) key substitution.",
        body
    ))

    story.append(Paragraph("<b>2. Cryptographic Protocols & Mathematical Formulations</b>", h2_style))
    story.append(Paragraph(
        "<b>Phase I: Diffie-Hellman Key Exchange (RFC 3526 Group 14)</b><br/>"
        "Parameters: p (2048-bit safe prime), generator g = 2.<br/>"
        "• Alice selects private a in [2, p-2] and computes public key A = g<sup>a</sup> mod p.<br/>"
        "• Bob selects private b in [2, p-2] and computes public key B = g<sup>b</sup> mod p.<br/>"
        "• Parties exchange A and B across the open channel.<br/>"
        "• Alice computes: K<sub>shared</sub> = B<sup>a</sup> mod p = (g<sup>b</sup>)<sup>a</sup> mod p = g<sup>ab</sup> mod p.<br/>"
        "• Bob computes: K<sub>shared</sub> = A<sup>b</sup> mod p = (g<sup>a</sup>)<sup>b</sup> mod p = g<sup>ab</sup> mod p.<br/>"
        "By the Discrete Logarithm Problem (DLP), an eavesdropper cannot derive a, b, or g<sup>ab</sup> mod p.",
        body
    ))

    story.append(Paragraph(
        "<b>Phase II: Key Derivation Function (HKDF-SHA256, RFC 5869)</b><br/>"
        "The raw shared secret is processed with HKDF-SHA256 using info='secure-chat-lab' to produce 64 bytes of output keying material (OKM):<br/>"
        "• K<sub>AES</sub> = OKM[0..31] (256-bit AES encryption key)<br/>"
        "• K<sub>HMAC</sub> = OKM[32..63] (256-bit HMAC authentication key)<br/>"
        "Key separation prevents cross-protocol cryptographic interactions.",
        body
    ))

    story.append(Paragraph(
        "<b>Phase III: AES-256-CBC Payload Encryption</b><br/>"
        "Each plaintext message is padded with PKCS#7 to a multiple of 16 bytes. A fresh random 128-bit IV is generated per packet. Ciphertext blocks are generated as C<sub>0</sub> = IV, C<sub>i</sub> = E<sub>K_AES</sub>(P<sub>i</sub> ⊕ C<sub>i-1</sub>).",
        body
    ))

    story.append(Paragraph(
        "<b>Phase IV: Encrypt-then-MAC Authentication & Packet Serialization</b><br/>"
        "Encrypt-then-MAC (EtM) protects against chosen-ciphertext and padding oracle attacks. A 64-bit monotonic sequence counter (Seq) prevents replay attacks:<br/>"
        "• Tag = HMAC-SHA256<sub>K_HMAC</sub>(Seq || IV || Ciphertext)<br/>"
        "• Wire Packet = Seq (8B) || IV (16B) || Ciphertext (NB) || Tag (32B)",
        body
    ))

    story.append(Paragraph(
        "<b>Phase V: Receiver Decryption & Anti-Replay Verification Pipeline</b><br/>"
        "1. <b>Verify HMAC First:</b> Recompute HMAC over Seq || IV || C. If invalid, drop immediately. Decryption is never attempted on untrusted data.<br/>"
        "2. <b>Verify Sequence Number:</b> Confirm Seq &gt; Recv_Seq. If Seq &le; Recv_Seq, reject as duplicate.<br/>"
        "3. <b>Decrypt & Unpad:</b> Decrypt with AES-256-CBC using K<sub>AES</sub> and IV, remove PKCS#7 padding, and deliver to user.",
        body
    ))

    # Attack Summary Table with Paragraph wrapped cells
    attack_data = [
        [
            Paragraph("<b>Attack Scenario</b>", table_header),
            Paragraph("<b>Adversarial Mechanism</b>", table_header),
            Paragraph("<b>System Detection & Defense</b>", table_header)
        ],
        [
            Paragraph("<b>Passive Eavesdropping</b>", table_cell),
            Paragraph("Captures raw wire packets (Seq, IV, C, Tag) transmitted over network.", table_cell),
            Paragraph("Eve sees only high-entropy pseudorandom bytes. Without K<sub>AES</sub>, decryption is computationally infeasible.", table_cell)
        ],
        [
            Paragraph("<b>Active Tampering</b>", table_cell),
            Paragraph("Flips a single bit in the ciphertext payload (C[2] ^= 0x01) during transit.", table_cell),
            Paragraph("HMAC verification fails immediately; packet is rejected before decryption.", table_cell)
        ],
        [
            Paragraph("<b>Replay Attack</b>", table_cell),
            Paragraph("Re-injects a previously captured legitimate packet into the channel.", table_cell),
            Paragraph("Sequence number check fails (Seq &le; Recv_Seq); packet is dropped.", table_cell)
        ],
        [
            Paragraph("<b>Man-in-the-Middle</b>", table_cell),
            Paragraph("Eve intercepts public DH parameters (A, B) and substitutes fake values.", table_cell),
            Paragraph("Demonstrates vulnerability of unauthenticated DH; highlights the requirement for PKI / digital signatures.", table_cell)
        ]
    ]
    t = Table(attack_data, colWidths=[1.5*inch, 2.3*inch, 3.1*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e3a8a")),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")])
    ]))
    story.append(KeepTogether([
        Paragraph("<b>Table 1: Adversarial Scenarios and Defense Mechanisms</b>", h2_style),
        Spacer(1, 3),
        t
    ]))
    story.append(Spacer(1, 10))

    # ==========================================
    # SECTION 5: SCREENSHOTS
    # ==========================================
    story.append(PageBreak())
    story.append(Paragraph("Screenshots", h1_style))
    story.append(Paragraph("The following empirical test captures demonstrate each phase of the application running across normal operations and active adversarial conditions.", body))

    screenshots_info = [
        ("screenshots/fig1_initial_state.png", "Figure 1: System Initial State (Unsecured channel, Alice, Eve, Bob panels with controls)."),
        ("screenshots/fig2_key_exchange.png", "Figure 2: Animated Diffie-Hellman Key Exchange and HKDF-SHA256 key derivation log."),
        ("screenshots/fig3_alice_bob_chat.png", "Figure 3: Secure End-to-End Chat. Plaintext visible only to Alice and Bob; Eve observes only raw ciphertext, IV, and HMAC."),
        ("screenshots/fig4_tamper_attack_rejected.png", "Figure 4: Active Tampering Attack. Eve flips a single bit in the ciphertext; Bob immediately rejects with 'HMAC verification FAILED'."),
        ("screenshots/fig5_replay_attack_rejected.png", "Figure 5: Replay Attack. Eve re-transmits a captured packet; Bob rejects with 'REPLAY detected - sequence 1 already seen'."),
        ("screenshots/fig6_mitm_exchange.png", "Figure 6: Man-in-the-Middle Key Exchange. Eve intercepts public keys, establishing separate shared secrets with Alice and Bob. Status warns 'COMPROMISED (MITM)'."),
        ("screenshots/fig7_mitm_intercepted_message.png", "Figure 7: MITM Attack Execution. Eve decrypts Alice's message, modifies the text to '[edited by Eve]', and re-encrypts for Bob.")
    ]

    for img_path, caption in screenshots_info:
        if os.path.exists(img_path):
            img = Image(img_path, width=6.5*inch, height=3.35*inch)
            story.append(KeepTogether([
                img,
                Spacer(1, 4),
                Paragraph(caption, caption_style),
                Spacer(1, 6)
            ]))

    # ==========================================
    # SECTION 6: CODE
    # ==========================================
    story.append(PageBreak())
    story.append(Paragraph("Code", h1_style))
    story.append(Paragraph(
        "Below is the complete, self-contained Python source code (<code>secure_chat_lab.py</code>) implementing the cryptographic protocol (Diffie-Hellman RFC 3526, HKDF-SHA256, AES-256-CBC, and HMAC-SHA256) alongside the interactive Tkinter GUI:",
        body
    ))

    with open("secure_chat_lab.py", "r", encoding="utf-8") as f:
        code_lines = f.readlines()

    chunk_size = 55
    for i in range(0, len(code_lines), chunk_size):
        chunk = "".join(code_lines[i:i+chunk_size])
        p = Preformatted(chunk, code_style)
        tbl = Table([[p]], colWidths=[6.9*inch])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(KeepTogether([tbl]))
        story.append(Spacer(1, 8))

    # ==========================================
    # SECTION 7: REFERENCES
    # ==========================================
    story.append(PageBreak())
    story.append(Paragraph("References", h1_style))
    refs = [
        "1. <b>Diffie, W., & Hellman, M. (1976).</b> New directions in cryptography. <i>IEEE Transactions on Information Theory</i>, 22(6), 644-654.",
        "2. <b>Kivinen, T., & Kojo, M. (2003).</b> <i>More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)</i>. RFC 3526, Internet Engineering Task Force (IETF).",
        "3. <b>Krawczyk, H., & Eronen, P. (2010).</b> <i>HMAC-based Extract-and-Expand Key Derivation Function (HKDF)</i>. RFC 5869, Internet Engineering Task Force (IETF).",
        "4. <b>Krawczyk, H. (2001).</b> The order of encryption and authentication for protecting communications (or: How secure is SSL?). In <i>Advances in Cryptology — CRYPTO 2001</i> (pp. 310-331). Springer, Berlin, Heidelberg.",
        "5. <b>Bellare, M., & Namprempre, C. (2000).</b> Authenticated encryption: Relations among notions and analysis of the generic composition paradigm. In <i>Advances in Cryptology — ASIACRYPT 2000</i> (pp. 531-545). Springer, Berlin, Heidelberg.",
        "6. <b>National Institute of Standards and Technology (NIST). (2001).</b> <i>Advanced Encryption Standard (AES)</i>. Federal Information Processing Standards Publication (FIPS PUB 197).",
        "7. <b>National Institute of Standards and Technology (NIST). (2001).</b> <i>Recommendation for Block Cipher Modes of Operation: Methods and Techniques</i>. NIST Special Publication 800-38A.",
        "8. <b>Krawczyk, H., Bellare, M., & Canetti, R. (1997).</b> <i>HMAC: Keyed-Hashing for Message Authentication</i>. RFC 2104, Internet Engineering Task Force (IETF).",
        "9. <b>Stallings, W. (2017).</b> <i>Cryptography and Network Security: Principles and Practice</i> (7th ed.). Pearson Education.",
        "10. <b>Rescorla, E. (2018).</b> <i>The Transport Layer Security (TLS) Protocol Version 1.3</i>. RFC 8446, Internet Engineering Task Force (IETF)."
    ]
    for r in refs:
        story.append(Paragraph(r, bullet_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    print("PDF build complete: " + filename)

if __name__ == "__main__":
    build_pdf()
