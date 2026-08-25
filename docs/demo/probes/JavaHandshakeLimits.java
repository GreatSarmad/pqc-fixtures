// Probe: measure a post-quantum certificate chain against the JDK's own
// TLS limits, and report which of them it crosses.
//
// A handful of SunJSSE defaults decide whether a chain can be presented at
// all, and none of them is documented anywhere a developer looks before
// migrating:
//
//   jdk.tls.maxHandshakeMessageSize                    default 32,768 bytes
//   jdk.tls.server.maxInboundCertificateChainLength    default 8  (JDK 22+)
//   jdk.tls.client.maxInboundCertificateChainLength    default 10 (JDK 22+)
//   jdk.tls.maxCertificateChainLength                  default 10 (undifferentiated)
//
// JDK 22 split the chain-length limit in two (JDK-8313236). The server-side
// default is the tighter one: a Java server accepts at most 8 certificates
// from a connecting client by default, which is the mTLS direction most
// deployments care about.
//
// The Certificate handshake message carries the whole chain in DER, so the
// first limit is a budget shared by every certificate in it. A classical
// three-certificate RSA chain spends about 3 KB of that budget. A post-quantum
// one can spend all of it.
//
// This probe deliberately measures rather than handshakes: it needs no
// keystore, no server, and no ML-DSA support in the JDK's own providers, so it
// gives a usable answer on any JDK from 11 up. Where the JDK *can* parse the
// certificates, it reports that too — a JDK that cannot parse them will not
// serve them regardless of the size limits.
//
// Usage: java JavaHandshakeLimits.java <fixture-root>
// Exits 0 if every measured chain fits under both the size and the count
// limit, 1 otherwise.

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JavaHandshakeLimits {

    // SunJSSE's own defaults, applied when the system property is unset.
    private static final int DEFAULT_MAX_HANDSHAKE_MESSAGE = 32768;
    private static final int DEFAULT_MAX_INBOUND_SERVER = 8;
    private static final int DEFAULT_MAX_INBOUND_CLIENT = 10;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: java JavaHandshakeLimits.java <fixture-root>");
            System.exit(2);
        }
        Path root = Path.of(args[0]);

        int maxMessage = intProperty("jdk.tls.maxHandshakeMessageSize", DEFAULT_MAX_HANDSHAKE_MESSAGE);
        // The undifferentiated property, when set, is the floor for both
        // directions; otherwise each side falls back to its own default.
        int legacyChain = intProperty("jdk.tls.maxCertificateChainLength", -1);
        int maxInboundServer = intProperty("jdk.tls.server.maxInboundCertificateChainLength",
                legacyChain > 0 ? legacyChain : DEFAULT_MAX_INBOUND_SERVER);
        int maxInboundClient = intProperty("jdk.tls.client.maxInboundCertificateChainLength",
                legacyChain > 0 ? legacyChain : DEFAULT_MAX_INBOUND_CLIENT);
        // A chain has to satisfy whichever side will receive it; the server
        // side is the tighter default and the one mTLS runs into.
        int maxChain = Math.min(maxInboundServer, maxInboundClient);

        System.out.printf("  java                %s (%s)%n",
                System.getProperty("java.version"), System.getProperty("java.vendor"));
        System.out.printf("  maxHandshakeMessage %,d B%n", maxMessage);
        System.out.printf("  inbound to a server %d certificates%n", maxInboundServer);
        System.out.printf("  inbound to a client %d certificates%n", maxInboundClient);

        boolean allFit = true;
        for (String set : new String[] {"ml-dsa-65", "worst-case-tls", "deep-chain"}) {
            Path chain = root.resolve(set).resolve("INSECURE-TEST-fullchain.pem");
            if (!Files.exists(chain)) {
                System.out.printf("%n  %s%n    SKIPPED           no fixture at %s%n", set, chain);
                continue;
            }
            allFit &= report(set, chain, maxMessage, maxChain);
        }

        System.out.printf("%n  RESULT              %s%n",
                allFit ? "PASS — every chain fits under both limits"
                       : "FAIL — at least one chain cannot be presented with default settings");
        System.exit(allFit ? 0 : 1);
    }

    private static boolean report(String label, Path chainPem, int maxMessage, int maxChain)
            throws Exception {
        System.out.printf("%n  %s%n", label);

        List<byte[]> ders = new ArrayList<>();
        String parseNote;
        try (InputStream in = Files.newInputStream(chainPem)) {
            // generateCertificates reads the whole PEM bundle. It throws if the
            // JDK's providers do not recognise the signature algorithm, which
            // is itself the answer for older JDKs.
            Collection<? extends java.security.cert.Certificate> certs =
                    CertificateFactory.getInstance("X.509").generateCertificates(in);
            for (java.security.cert.Certificate c : certs) {
                ders.add(c.getEncoded());
            }
            parseNote = "parsed by this JDK";
        } catch (Exception e) {
            System.out.printf("    certificates      NOT PARSEABLE: %s%n",
                    e.getClass().getSimpleName() + ": " + e.getMessage());
            System.out.printf("    verdict           cannot be presented — the JDK rejects the chain before any size limit applies%n");
            return false;
        }

        int total = 0;
        for (byte[] der : ders) {
            total += der.length;
        }
        // Each certificate in a TLS 1.3 CertificateEntry carries a 3-byte
        // length prefix and a 2-byte extensions field; the message itself adds
        // a 1-byte context length and a 3-byte list length. Counting them keeps
        // the comparison honest rather than flattering.
        int onWire = 4 + ders.size() * 5 + total;

        System.out.printf("    certificates      %d (%s)%n", ders.size(), parseNote);
        System.out.printf("    chain DER         %,d B%n", total);
        System.out.printf("    handshake message %,d B including TLS 1.3 framing%n", onWire);

        boolean fitsSize = onWire <= maxMessage;
        boolean fitsCount = ders.size() <= maxChain;
        System.out.printf("    vs size limit     %s (%,d B of %,d B, %.0f%%)%n",
                fitsSize ? "fits" : "EXCEEDED", onWire, maxMessage, 100.0 * onWire / maxMessage);
        System.out.printf("    vs chain limit    %s (%d of %d, the tighter of the two directions)%n",
                fitsCount ? "fits" : "EXCEEDED", ders.size(), maxChain);

        return fitsSize && fitsCount;
    }

    private static int intProperty(String name, int fallback) {
        String raw = System.getProperty(name);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
