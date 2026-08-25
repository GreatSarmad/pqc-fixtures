# DRAFT — blog post

**Status:** draft. The Node numbers are measured and quotable. The Java and
PostgreSQL sections are outlined but deliberately unwritten: their numbers come
from the `demo.yml` transcript, and nothing goes in this post that a reader
cannot reproduce with `docs/demo/run.sh`. Publishing is a founder action.

**Working title:** Your post-quantum certificate is 65× bigger. Here is what
notices first.

**Alternative titles:** · What breaks first when certificates get 65× bigger
· The post-quantum migration bug you will hit before you hit any crypto bug

---

## The shape of the argument

Most post-quantum migration writing is about algorithms. Almost none of it is
about size, and size is what developers hit first — months before any crypto
decision reaches them, and in code that has nothing to do with cryptography.

The post should make one claim and prove it four times: **a post-quantum
certificate breaks things that are not cryptography, and the errors it
produces do not mention certificates.** Every proof is a script the reader can
run.

## Opening

Lead with the smallest surprise, not the biggest. The biggest — a 50 KB
SLH-DSA certificate — is easy to wave away as exotic. The smallest is not:

> A plain ML-DSA-65 certificate chain, the mainstream post-quantum choice, is
> 23,088 bytes of PEM. Node's default HTTP header budget is 16,384. If anything
> in your stack forwards a client certificate in a header — and if you run mTLS
> behind nginx, an ALB, or Envoy, something does — that request does not
> arrive. It does not arrive as `431 Request Header Fields Too Large` either.
> The server logs `HPE_HEADER_OVERFLOW`, the client gets `ECONNRESET`, and
> nothing anywhere says the word "certificate".

Then the size table, because it is the whole argument in six rows:

| Certificate | PEM | URL-escaped for a header |
|---|---:|---:|
| RSA-2048 leaf | 1,070 B | 1,152 B |
| ML-DSA-65 leaf | 7,753 B | 8,461 B |
| ML-DSA-65 chain (3) | 23,088 B | 25,200 B |
| SLH-DSA-SHA2-256f leaf | 68,248 B | 74,474 B |

65× from the first row to the last. Node's header limit sits at 16,384.

## Section 1 — Node, the header path (measured, quotable)

The mTLS-behind-a-proxy pattern, named concretely: nginx
`ssl_client_escaped_cert`, AWS ALB `x-amzn-mtls-clientcert`, Envoy
`x-forwarded-client-cert`. Show `node-cert-header.mjs`, show the four results,
dwell on the ML-DSA chain row.

The point to land: the failure is silent in the way that costs the most
debugging time. It is not a validation error. It is a connection reset from a
parser that gave up before any application code ran.

## Section 2 — Node, the TLS path (measured, quotable)

The nuance that makes the post trustworthy rather than alarmist: Node 25.6.0
links OpenSSL 3.5.5, and ML-DSA works. Handshake completes, chain verifies,
`TLS_AES_256_GCM_SHA384`. The post should say so plainly — most of this is
going to work.

Then SLH-DSA: `ERR_SSL_UNKNOWN_CERTIFICATE_TYPE`, thrown by
`tls.createSecureContext` before `listen()`. The server does not fail to
handshake; it fails to start. "Does your runtime support post-quantum
certificates" turns out not to be one question.

## Section 3 — Java (outlined; needs the CI transcript)

Two defaults nobody reads before migrating:
`jdk.tls.maxHandshakeMessageSize` (32,768 B, a budget the *whole chain*
shares) and the certificate-count limit that JDK 22 split in two —
`jdk.tls.server.maxInboundCertificateChainLength` defaults to 8, the client one
to 10. The server-side 8 is the mTLS direction.

The `deep-chain` preset exists precisely for this: ten certificates, above the
server-side default. Fill in the measured handshake-message sizes from the
transcript before writing this section.

## Section 4 — PostgreSQL (outlined; needs the CI transcript)

Two failures, one boring and one interesting. The boring one: `varchar(4096)`,
chosen years ago by someone who never measured a certificate, now too small by
5×. The interesting one: btree's ~2,704-byte index row limit, which turns
"index the certificate column" from a working migration into a failing one.

The fix is a hash index on `digest(pem, 'sha256')`, which is worth showing —
the post should leave readers with a change to make, not only a fear.

## Closing

The honest summary is not "post-quantum breaks everything". It is:

- Most things work. ML-DSA over TLS mostly just works today.
- The things that break are size limits in non-crypto code: header budgets,
  handshake-message caps, column widths, index row limits.
- They break with errors that never name the cause.
- All of them are findable *before* you migrate, in an afternoon, with
  certificates of the right size.

Then the tool, in one paragraph and one command — not a pitch:

```bash
pqc-fixtures gen --preset worst-case-tls --out ./testdata
```

## Things to check before publishing

- [ ] Re-run `docs/demo/run.sh` on the day of publication and re-quote every
      number; the pinned engine or Node may have moved.
- [ ] Fill Sections 3 and 4 from the `demo.yml` transcript.
- [ ] Confirm the nginx / ALB / Envoy header names against current docs.
- [ ] Decide whether the GIF is worth it. The transcript is legible as text,
      and a GIF that shows a connection reset is not visually interesting.
      A static terminal capture of the result table may be the better asset.
- [ ] State the tool's status honestly: `v0.0.1` pre-release, macOS binaries
      unsigned (ADR-013), and the `xattr` workaround in the release notes.
