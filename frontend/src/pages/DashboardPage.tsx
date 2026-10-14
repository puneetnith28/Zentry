import { useState } from 'react'
import { Link } from 'react-router-dom'

const FAQ_ITEMS = [
  {
    q: 'DOES THIS SCANNER RUN ACTIVE EXPLOITS OR FUZZING PAYLOADS?',
    a: 'No. Zentry enforces a strictly non-intrusive, passive-first security posture inspection. Assessments consist entirely of native cryptographic handshakes, HTTP header audits, non-blocking TCP connect checks, and Certificate Transparency log queries. No payloads or fuzzing are ever dispatched.',
  },
  {
    q: 'HOW DOES THE WEIGHTED RISK SCORING ALGORITHM FUNCTION?',
    a: 'Zentry computes a deterministic 0 to 100 risk score based on finding severity weights: Critical (25), High (15), Medium (8), Low (3), and Info (1). Scores from 75–100 indicate Critical Risk, 50–74 High Risk, 25–49 Moderate Risk, and 1–24 Low Risk.',
  },
  {
    q: 'WHAT OPERATIONAL SAFEGUARDS MITIGATE SSRF ATTACKS?',
    a: 'Every target hostname is resolved against DNS before dispatch to verify that underlying IP addresses do not belong to private networks, loopbacks (127.0.0.0/8), or cloud metadata endpoints (169.254.169.254). Outbound connections through the safe proxy reject forbidden ranges automatically.',
  },
  {
    q: 'ARE SCAN RECORDS PERSISTED WITH DETERMINISTIC REPRODUCIBILITY?',
    a: 'Yes. Every evaluation produces a timestamped snapshot recording raw header values, verified X.509 certificate chains, exposed port states, and passive fingerprint signatures stored immutably in PostgreSQL.',
  },
  {
    q: 'HOW ARE EXECUTIVE PDF REPORTS GENERATED?',
    a: 'Scan findings are compiled into structured, styled HTML documents and rendered into publication-ready PDF executive reports using WeasyPrint and Jinja2 with zero external browser dependencies.',
  },
]

export function DashboardPage() {
  const [openFaq, setOpenFaq] = useState<number | null>(0)

  return (
    <div className="w-full bg-[#2e4742] text-[#10201d]">
      {/* ------------------------------------------------------------- */}
      {/* 1. HERO SECTION (Color Palette: Pine Slate #2e4742, Salmon Coral #e97b77, Crimson Rust #671912) */}
      {/* ------------------------------------------------------------- */}
      <section className="border-b-2 border-[#10201d] bg-[#2e4742] px-4 py-12 sm:px-8 sm:py-20 lg:py-24 text-white">
        <div className="mx-auto max-w-7xl">
          <div className="grid gap-12 lg:grid-cols-[1.1fr_0.9fr] lg:items-center">
            {/* Left Column: Bold Headline & Lead */}
            <div>
              {/* Dual Neo-Brutalist Badges */}
              <div className="flex flex-wrap items-center gap-2">
                <span className="border-2 border-[#10201d] bg-[#e97b77] px-3 py-1 font-mono text-xs font-black uppercase text-[#10201d] brutal-shadow-sm">
                  ONE AUDIT. CONNECTED POSTURE.
                </span>
                <span className="border-2 border-[#10201d] bg-[#10201d] px-3 py-1 font-mono text-xs font-black uppercase text-[#e97b77] brutal-shadow-sm">
                  OCTOBER 2026 EDITION
                </span>
              </div>

              {/* Main Headline with Box Highlight */}
              <h1 className="mt-8 font-mono text-5xl font-black tracking-tight text-white sm:text-6xl lg:text-7xl leading-[1.05]">
                ONE SCAN.<br />
                ONE VERIFIED<br />
                <span className="inline-block border-4 border-[#10201d] bg-[#e97b77] text-[#10201d] px-4 py-1 mt-2 brutal-shadow">
                  HANDOFF.
                </span>
              </h1>

              <p className="mt-6 max-w-xl font-sans text-lg font-medium text-slate-200 leading-relaxed">
                A security engineer audits public attack surfaces. Zentry's deterministic engine verifies cryptographic suites, HTTP framing headers, exposed network ports, and passive OSINT, then produces an explainable report.
              </p>

              {/* Primary Action Button */}
              <div className="mt-8 flex flex-wrap items-center gap-4">
                <Link
                  to="/scans/new"
                  className="inline-flex items-center gap-2 border-2 border-[#10201d] bg-[#e97b77] px-6 py-3.5 font-mono text-sm font-black uppercase tracking-wider text-[#10201d] brutal-shadow hover:bg-[#df6d69] transition-transform active:translate-x-1 active:translate-y-1 cursor-pointer"
                >
                  <span>INITIALIZE POSTURE AUDIT</span>
                  <span className="text-base font-black">↗</span>
                </Link>
              </div>

              {/* Small Footnote Indicator */}
              <div className="mt-6 flex items-center gap-2 font-mono text-xs font-bold text-slate-300">
                <span className="size-2.5 rounded-full border border-[#10201d] bg-[#e97b77]" />
                <span>Deterministic pre-verification audit trail • 100% Explainable & Non-intrusive</span>
              </div>
            </div>

            {/* Right Column: Two Finora-style Offset Cards */}
            <div className="space-y-6">
              {/* Top Card: Light Paper Report Card */}
              <div className="border-2 border-[#10201d] bg-[#f7f3ee] text-[#10201d] p-6 brutal-shadow-lg">
                <div className="flex items-center justify-between border-b-2 border-[#10201d] pb-3">
                  <span className="border border-[#10201d] bg-[#e97b77] px-2 py-0.5 font-mono text-[11px] font-black uppercase text-[#10201d]">
                    THE TARGET REPORT
                  </span>
                  <span className="border border-[#10201d] bg-[#10201d] px-2 py-0.5 font-mono text-[11px] font-black uppercase text-[#e97b77]">
                    VERIFIED
                  </span>
                </div>
                <h3 className="mt-4 font-mono text-base font-black text-[#10201d] leading-snug">
                  Unchecked TLS cipher suites and missing HSTS framing fail outright without defensive verification. Pass the target to the audit matrix to confirm exact risk scoring.
                </h3>
                <p className="mt-3 font-mono text-[11px] font-bold text-slate-600 uppercase tracking-wider">
                  REPORT SUMMARY, SYNTHESIZED FOR SECURITY REVIEWS
                </p>
              </div>

              {/* Bottom Card: Coral & Paper Card with Table of Checks */}
              <div className="border-2 border-[#10201d] bg-white text-[#10201d] p-6 brutal-shadow-lg">
                <div className="flex items-center justify-between border-b-2 border-[#10201d] pb-3">
                  <span className="border border-[#10201d] bg-[#e97b77] px-2.5 py-0.5 font-mono text-[11px] font-black uppercase text-[#10201d]">
                    DEFENSIVE CRITERIA
                  </span>
                  <span className="border border-[#10201d] bg-[#f7f3ee] px-2.5 py-0.5 font-mono text-[11px] font-black uppercase text-[#10201d]">
                    READ BACK ✓
                  </span>
                </div>

                <h3 className="mt-3 font-mono text-lg font-black text-[#10201d]">
                  THE ASSESSMENT HAS A TRAIL.
                </h3>

                <div className="mt-4 space-y-2 border-t-2 border-[#10201d] pt-3 font-mono text-xs">
                  <div className="flex justify-between py-1 border-b border-[#10201d]/20">
                    <span className="font-bold">HTTP Strict-Transport-Security</span>
                    <span className="font-black text-[#10201d]">Pass • max-age ≥ 31536000</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-[#10201d]/20">
                    <span className="font-bold">X.509 Chain & SAN Match</span>
                    <span className="font-black text-[#10201d]">Verified • 100% Valid Chain</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-[#10201d]/20">
                    <span className="font-bold">TCP Port Perimeter Probes</span>
                    <span className="font-black text-[#10201d]">Bounded • No DB ports open</span>
                  </div>
                </div>

                <div className="mt-4 border-2 border-[#10201d] bg-[#e97b77] p-2.5 font-mono text-xs font-black text-[#10201d] brutal-shadow-sm">
                  Out of scope? Internal RFC 1918 IPs rejected by SSRF safe proxy gate.
                </div>
              </div>
            </div>
          </div>

          {/* 4 Bottom Strip Banners */}
          <div className="mt-16 grid grid-cols-2 gap-4 border-t-2 border-[#10201d] pt-8 lg:grid-cols-4">
            <div className="border-2 border-[#10201d] bg-[#f7f3ee] text-[#10201d] p-4 brutal-shadow-sm">
              <div className="font-mono text-[10px] font-black uppercase text-slate-600">01 / CALCULATION</div>
              <div className="mt-1 font-mono text-sm font-black text-[#10201d]">Deterministic Risk Score</div>
            </div>
            <div className="border-2 border-[#10201d] bg-[#f7f3ee] text-[#10201d] p-4 brutal-shadow-sm">
              <div className="font-mono text-[10px] font-black uppercase text-slate-600">02 / CRYPTOGRAPHY</div>
              <div className="mt-1 font-mono text-sm font-black text-[#10201d]">Native TLS Primitives</div>
            </div>
            <div className="border-2 border-[#10201d] bg-[#f7f3ee] text-[#10201d] p-4 brutal-shadow-sm">
              <div className="font-mono text-[10px] font-black uppercase text-slate-600">03 / POLICY AUDITS</div>
              <div className="mt-1 font-mono text-sm font-black text-[#10201d]">5 Core Inspection Modules</div>
            </div>
            <div className="border-2 border-[#10201d] bg-[#f7f3ee] text-[#10201d] p-4 brutal-shadow-sm">
              <div className="font-mono text-[10px] font-black uppercase text-slate-600">04 / AUDIT TRAIL</div>
              <div className="mt-1 font-mono text-sm font-black text-[#10201d]">Tamper-Proof PDF Export</div>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------- */}
      {/* 2. THE RECORDED HANDOFF AUDIT RECEIPT */}
      {/* ------------------------------------------------------------- */}
      <section className="border-b-2 border-[#10201d] bg-[#f7f3ee] px-4 py-16 sm:px-8 sm:py-20">
        <div className="mx-auto max-w-5xl">
          {/* Section Header */}
          <div className="mb-8">
            <span className="border-2 border-[#10201d] bg-[#e97b77] px-2.5 py-0.5 font-mono text-xs font-black uppercase text-[#10201d] brutal-shadow-sm">
              THE RECORDED AUDIT
            </span>
            <div className="mt-4 flex flex-wrap items-baseline justify-between gap-4">
              <h2 className="font-mono text-4xl font-black text-[#10201d] sm:text-5xl">
                A REAL SCAN.<br />A READABLE RECEIPT.
              </h2>
              <p className="max-w-md font-sans text-sm font-bold text-slate-700">
                ZENTRY-RECORD-01 is a verified defensive run. The deterministic engine evaluated all security checks; these findings are independently computed and verified.
              </p>
            </div>
          </div>

          {/* Paper Report Sheet */}
          <div className="border-4 border-[#10201d] bg-white p-6 sm:p-10 brutal-shadow-xl">
            <div className="flex flex-wrap items-center justify-between border-b-2 border-[#10201d] pb-4">
              <span className="border border-[#10201d] bg-[#e97b77] px-3 py-1 font-mono text-xs font-black uppercase text-[#10201d] brutal-shadow-sm">
                RECORDED STATUS: COMPLETE
              </span>
              <div className="text-right font-mono text-xs font-bold text-slate-600">
                <div>OCTOBER 15, 2026</div>
                <div>Deterministic Engine • 5 Verified Engines</div>
              </div>
            </div>

            <h3 className="mt-6 font-mono text-2xl font-black text-[#10201d]">
              POSTURE AUDIT RECORD → PRODUCTION TARGET #1
            </h3>

            {/* Finding Rows */}
            <div className="mt-8 space-y-6">
              {/* Item 01 */}
              <div>
                <div className="flex items-center gap-3">
                  <span className="border border-[#10201d] bg-[#e97b77] px-2 py-0.5 font-mono text-[11px] font-black text-[#10201d]">
                    01 / HTTP HEADERS
                  </span>
                  <span className="font-mono text-sm font-bold text-[#10201d]">
                    ✓ Strict-Transport-Security & CSP Verification
                  </span>
                </div>
                <div className="mt-2 border-2 border-[#10201d] bg-[#f7f3ee] p-3 font-mono text-xs font-bold text-[#10201d] brutal-shadow-sm">
                  HSTS: max-age=31536000; includeSubDomains • CSP: default-src 'self' • X-Frame-Options: DENY
                </div>
                <p className="mt-1 font-sans text-xs text-slate-600">
                  Target policy prevents clickjacking and enforces HTTPS transit across all subdomains.
                </p>
              </div>

              {/* Item 02 */}
              <div>
                <div className="flex items-center gap-3">
                  <span className="border border-[#10201d] bg-[#f7f3ee] px-2 py-0.5 font-mono text-[11px] font-black text-[#10201d]">
                    02 / SSL & TLS
                  </span>
                  <span className="font-mono text-sm font-bold text-[#10201d]">
                    ✓ Cryptographic Key Length & Expiry Audit
                  </span>
                </div>
                <div className="mt-2 border-2 border-[#10201d] bg-[#f7f3ee] p-3 font-mono text-xs font-bold text-[#10201d] brutal-shadow-sm">
                  Protocol: TLSv1.3 • Cipher: TLS_AES_256_GCM_SHA384 • Certificate Expiry: 248 Days Remaining
                </div>
                <p className="mt-1 font-sans text-xs text-slate-600">
                  Native OpenSSL primitives verify that cipher configuration has zero legacy SSLv3 or weak RC4 algorithms.
                </p>
              </div>

              {/* Item 03 */}
              <div>
                <div className="flex items-center gap-3">
                  <span className="border border-[#10201d] bg-[#e97b77] px-2 py-0.5 font-mono text-[11px] font-black text-[#10201d]">
                    03 / EXPOSED PORTS
                  </span>
                  <span className="font-mono text-sm font-bold text-[#10201d]">
                    ✓ Non-Blocking TCP Connect Probes
                  </span>
                </div>
                <div className="mt-2 border-2 border-[#10201d] bg-[#f7f3ee] p-3 font-mono text-xs font-bold text-[#10201d] brutal-shadow-sm">
                  Surveyed Ports: 21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080 • Open: 80, 443 • DB Ports: Filtered
                </div>
                <p className="mt-1 font-sans text-xs text-slate-600">
                  No administrative interfaces or database ports exposed to public ingress.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------- */}
      {/* 3. THREE CORE PRINCIPLES */}
      {/* ------------------------------------------------------------- */}
      <section className="border-b-2 border-[#10201d] bg-[#2e4742] text-white px-4 py-16 sm:px-8 sm:py-20">
        <div className="mx-auto max-w-5xl">
          <span className="border-2 border-[#10201d] bg-[#e97b77] px-3 py-1 font-mono text-xs font-black uppercase text-[#10201d] brutal-shadow-sm">
            WHY THIS AUDIT MATTERS
          </span>

          <div className="mt-10 divide-y-2 divide-[#10201d] border-t-2 border-b-2 border-[#10201d]">
            {/* Principle 01 */}
            <div className="grid gap-6 py-8 md:grid-cols-[60px_1fr_1.5fr] items-start">
              <span className="font-mono text-base font-black text-[#e97b77]">01</span>
              <h3 className="font-mono text-2xl font-black text-white leading-tight">
                KEEP THE CONTEXT CONNECTED.
              </h3>
              <p className="font-sans text-base font-medium text-slate-200 leading-relaxed">
                The cryptographic cipher suites, HTTP framing rules, open socket states, and passive technology signatures all link back to the exact same reproducible scan receipt.
              </p>
            </div>

            {/* Principle 02 */}
            <div className="grid gap-6 py-8 md:grid-cols-[60px_1fr_1.5fr] items-start">
              <span className="font-mono text-base font-black text-[#e97b77]">02</span>
              <h3 className="font-mono text-2xl font-black text-white leading-tight">
                KEEP THE ACTIONS BOUNDED.
              </h3>
              <p className="font-sans text-base font-medium text-slate-200 leading-relaxed">
                A security scanner cannot perform destructive actions. The execution layer enforces strict non-intrusive handshakes, rate boundaries, and immediate SSRF rejection on loopback addresses.
              </p>
            </div>

            {/* Principle 03 */}
            <div className="grid gap-6 py-8 md:grid-cols-[60px_1fr_1.5fr] items-start">
              <span className="font-mono text-base font-black text-[#e97b77]">03</span>
              <h3 className="font-mono text-2xl font-black text-white leading-tight">
                SEE WHAT ACTUALLY LANDED.
              </h3>
              <p className="font-sans text-base font-medium text-slate-200 leading-relaxed">
                Independent scanning engines verify each defense layer with zero black-box AI hallucination. Deterministic, audited Python code computes the final weighted risk score.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------- */}
      {/* 4. THREE CARDS */}
      {/* ------------------------------------------------------------- */}
      <section id="how-it-works" className="border-b-2 border-[#10201d] bg-[#f7f3ee] px-4 py-16 sm:px-8 sm:py-20">
        <div className="mx-auto max-w-6xl">
          <span className="border-2 border-[#10201d] bg-[#e97b77] px-3 py-1 font-mono text-xs font-black uppercase text-[#10201d] brutal-shadow-sm">
            HOW IT WORKS
          </span>

          <h2 className="mt-6 font-mono text-4xl font-black text-[#10201d] sm:text-5xl">
            FROM AUDIT<br />TO READ BACK.
          </h2>

          <div className="mt-12 grid gap-6 md:grid-cols-3">
            {/* Box 1 */}
            <div className="border-2 border-[#10201d] bg-white p-6 brutal-shadow-lg flex flex-col justify-between">
              <div>
                <span className="font-mono text-xs font-black text-[#10201d]">01</span>
                <h4 className="mt-3 font-mono text-lg font-black text-[#10201d]">READ THE TARGET.</h4>
                <p className="mt-3 font-sans text-xs font-medium text-slate-700 leading-relaxed">
                  Zentry queries public DNS and verifies hostname legality through strict SSRF gates before initiating outbound handshakes.
                </p>
              </div>
            </div>

            {/* Box 2 */}
            <div className="border-2 border-[#10201d] bg-[#e97b77] p-6 brutal-shadow-lg flex flex-col justify-between">
              <div>
                <span className="font-mono text-xs font-black text-[#10201d]">02</span>
                <h4 className="mt-3 font-mono text-lg font-black text-[#10201d]">BOUND THE ACTION.</h4>
                <p className="mt-3 font-sans text-xs font-medium text-[#10201d] leading-relaxed">
                  The engine evaluates SSL certificates, response headers, and exposed ports in strictly parallel, non-destructive execution passes.
                </p>
              </div>
            </div>

            {/* Box 3 */}
            <div className="border-2 border-[#10201d] bg-white p-6 brutal-shadow-lg flex flex-col justify-between">
              <div>
                <span className="font-mono text-xs font-black text-[#10201d]">03</span>
                <h4 className="mt-3 font-mono text-lg font-black text-[#10201d]">VERIFY THE RESULT.</h4>
                <p className="mt-3 font-sans text-xs font-medium text-slate-700 leading-relaxed">
                  Read findings back with deterministic 0-100 risk scoring. Export tamper-proof PDF executive receipts for immediate compliance audit review.
                </p>
              </div>
            </div>
          </div>

          <p className="mt-8 font-sans text-xs font-bold text-[#10201d] max-w-3xl">
            Deterministic code verifies each posture layer. A valid target submission is not proof of total invulnerability, and findings are flagged for engineering prioritization.
          </p>
        </div>
      </section>



      {/* ------------------------------------------------------------- */}
      {/* 6. ACCORDION FAQ */}
      {/* ------------------------------------------------------------- */}
      <section className="bg-[#f7f3ee] px-4 py-16 sm:px-8 sm:py-20">
        <div className="mx-auto max-w-5xl">
          <div className="grid gap-12 lg:grid-cols-[1fr_2fr] items-start">
            {/* FAQ Header */}
            <div>
              <span className="border-2 border-[#10201d] bg-[#e97b77] px-3 py-1 font-mono text-xs font-black uppercase text-[#10201d] brutal-shadow-sm">
                A FEW HONEST ANSWERS
              </span>
              <h2 className="mt-4 font-mono text-4xl font-black text-[#10201d]">
                WHAT TO KNOW.
              </h2>
              <p className="mt-3 font-sans text-sm font-medium text-slate-700">
                Transparent web security posture analysis with verifiable audit trails you can inspect.
              </p>
            </div>

            {/* Accordion List */}
            <div className="divide-y-2 divide-[#10201d] border-t-2 border-b-2 border-[#10201d]">
              {FAQ_ITEMS.map((item, idx) => {
                const isOpen = openFaq === idx
                return (
                  <div key={item.q} className="py-4">
                    <button
                      type="button"
                      onClick={() => setOpenFaq(isOpen ? null : idx)}
                      className="flex w-full items-center justify-between gap-4 text-left font-mono text-sm font-black text-[#10201d] hover:opacity-80 cursor-pointer"
                    >
                      <span>{item.q}</span>
                      <span className="flex size-7 items-center justify-center border-2 border-[#10201d] bg-[#e97b77] text-[#10201d] font-mono text-base font-black brutal-shadow-sm shrink-0">
                        {isOpen ? '—' : '+'}
                      </span>
                    </button>

                    {/* Highlighted box for open FAQ in Coral #e97b77 */}
                    {isOpen && (
                      <div className="mt-4 border-2 border-[#10201d] bg-[#e97b77] p-4 font-sans text-xs font-bold leading-relaxed text-[#10201d] brutal-shadow-sm">
                        {item.a}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------- */}
      {/* FOOTER */}
      {/* ------------------------------------------------------------- */}
      <footer className="border-t-2 border-[#10201d] bg-[#10201d] text-white px-4 py-8 sm:px-8 font-mono text-xs">
        <div className="mx-auto max-w-7xl flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="border border-[#10201d] bg-[#e97b77] text-[#10201d] px-2 py-0.5 font-bold">Z</span>
            <span className="font-bold">ZENTRY DEFENSIVE PLATFORM</span>
            <span className="text-slate-400">| VERSION 1.0.0</span>
          </div>
          <div className="text-slate-400">
            Authorized targets only. Zero exploitation. Deterministic verification.
          </div>
        </div>
      </footer>
    </div>
  )
}
