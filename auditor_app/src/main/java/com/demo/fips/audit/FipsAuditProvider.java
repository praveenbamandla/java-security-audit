package com.demo.fips.audit;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * JCA Security Provider &mdash; FIPS Audit Bridge
 *
 * <p>Sits at JCA position 1 and intercepts every {@code getInstance()} call.
 * Uses a two-layer classification to decide what to audit:</p>
 *
 * <ol>
 *   <li><b>BCFIPS probe</b> &mdash; calls {@code bcfips.getService(type, algorithm)}
 *       to determine whether the algorithm is FIPS-approved.  If BCFIPS
 *       does not recognise the algorithm in approved-only mode, it is
 *       classified as {@code DISALLOWED} and logged.</li>
 *   <li><b>Policy file</b> ({@code fips-policy.properties}) &mdash; flags
 *       configurations that are technically FIPS-valid but operationally
 *       weak or deprecated (e.g.&nbsp;AES/ECB, SHA-1, 3DES).  These are
 *       classified as {@code WEAK} and logged.</li>
 * </ol>
 *
 * <p>All actual cryptographic operations are delegated to native JCA
 * providers (SUN, SunJCE, etc.).  BCFIPS is used <em>only</em> as a
 * FIPS-compliance oracle and is never registered in the JCA provider
 * chain &mdash; this avoids the StackOverflowError caused by its internal
 * circular SecureRandom bootstrap.</p>
 *
 * <pre>
 * JVM arguments:
 *   -Djava.security.properties==security-audit.properties
 *   -Dorg.bouncycastle.fips.approved_only=true
 *   -Dfips.audit.log=C:\path\to\fips-audit.log   (default: fips-audit.log)
 *   -Dfips.audit.stack.depth=30                   (default: 20)
 * </pre>
 */
public final class FipsAuditProvider extends Provider {

    private static final String NAME    = "FipsAudit";
    private static final String VERSION = "1.0";
    private static final String INFO    =
            "FIPS Audit Bridge: logs non-FIPS JCA usage and delegates to native providers";

    /**
     * Re-entrancy guard: depth counter tracking nested entries into
     * getService / newInstance.  When depth &gt; 0 we are already inside
     * an audit-layer call and must bypass to avoid infinite recursion.
     */
    static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);

    /**
     * Tracks the full cipher transformation string detected during the
     * {@code getService()} lookup sequence (e.g.&nbsp;"AES/ECB/PKCS5Padding").
     *
     * <p>JCA calls {@code getService()} with the full transformation first,
     * then falls back to the base algorithm ("AES").  We capture the
     * transformation here so that {@code newInstance()} can extract the
     * mode and padding for a policy-file lookup.</p>
     */
    static final ThreadLocal<String> PENDING_CIPHER_TRANSFORM = new ThreadLocal<>();

    // ── Direct BCFIPS provider reference (NOT in JCA chain) ────────────

    private static volatile Provider bcfipsInstance;

    /** Configurable policy engine &mdash; loaded once on first use. */
    private static volatile FipsPolicy fipsPolicy;

    // ── BCFIPS management ──────────────────────────────────────────────

    /**
     * Register the BouncyCastleFipsProvider instance that this provider
     * uses as the FIPS-compliance oracle.  Not required &mdash; if omitted,
     * BCFIPS is auto-initialised on first use from the classpath.
     */
    public static void setBcfipsProvider(Provider bcfips) {
        bcfipsInstance = bcfips;
        System.err.println("[FipsAudit] BCFIPS provider set: "
                + bcfips.getName() + " v" + bcfips.getVersion()
                + " (FIPS oracle - NOT in JCA chain)");
    }

    public static Provider getBcfipsProvider() {
        return bcfipsInstance;
    }

    /**
     * Lazily creates and configures a BouncyCastleFipsProvider instance.
     * Called automatically on the first {@code getService()} invocation
     * when {@link #setBcfipsProvider} was not called explicitly.
     */
    private static synchronized Provider autoInitBcfips() {
        Provider p = bcfipsInstance;
        if (p != null) return p;
        try {
            Class<?> cls = Class.forName(
                    "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider");
            p = (Provider) cls.getDeclaredConstructor().newInstance();
            bcfipsInstance = p;
            System.err.println("[FipsAudit] BCFIPS auto-initialised: "
                    + p.getName() + " v" + p.getVersion()
                    + " (FIPS oracle - NOT in JCA chain)");
        } catch (Exception e) {
            System.err.println("[FipsAudit] WARNING: bc-fips not on classpath - "
                    + "audit limited to policy-file rules only: " + e);
        }
        return p;
    }

    // ── Policy engine ──────────────────────────────────────────────────

    static FipsPolicy policy() {
        if (fipsPolicy == null) {
            synchronized (FipsAuditProvider.class) {
                if (fipsPolicy == null) {
                    fipsPolicy = new FipsPolicy();
                }
            }
        }
        return fipsPolicy;
    }

    // ── Audit logger ───────────────────────────────────────────────────

    private static volatile Logger auditLog;
    private static volatile int stackDepth;

    static Logger auditLogger() {
        if (auditLog == null) {
            synchronized (FipsAuditProvider.class) {
                if (auditLog == null) {
                    stackDepth = Integer.parseInt(
                            System.getProperty("fips.audit.stack.depth", "20"));
                    auditLog = buildLogger();
                }
            }
        }
        return auditLog;
    }

    private static Logger buildLogger() {
        String logFile = System.getProperty("fips.audit.log", "fips-audit.log");
        Logger log = Logger.getLogger("com.demo.fips.audit");
        log.setUseParentHandlers(false);
        log.setLevel(Level.ALL);

        ConsoleHandler ch = new ConsoleHandler();
        ch.setFormatter(new PlainFormatter());
        ch.setLevel(Level.ALL);
        log.addHandler(ch);

        try {
            FileHandler fh = new FileHandler(logFile, true);
            fh.setFormatter(new PlainFormatter());
            fh.setLevel(Level.ALL);
            log.addHandler(fh);
            System.err.println("[FipsAudit] Audit log -> " + logFile);
        } catch (Exception e) {
            System.err.println("[FipsAudit] WARNING: cannot open log file '"
                    + logFile + "': " + e.getMessage() + " - stderr only");
        }
        return log;
    }

    // ── Constructor ────────────────────────────────────────────────────

    public FipsAuditProvider() {
        super(NAME, VERSION, INFO);
        System.err.println("[FipsAudit] Provider instantiated.");
    }

    // ── getService ─────────────────────────────────────────────────────
    //
    //  Called by JCA for every getInstance() lookup.
    //
    //  SecureRandom is ALWAYS routed to native (SUN) to avoid BCFIPS's
    //  internal circular bootstrap (StackOverflowError).
    //
    //  A depth counter prevents re-entrant calls during BCFIPS's
    //  getService (e.g. internal KeyGenerator / Cipher lookup).
    //

    @Override
    public Provider.Service getService(String type, String algorithm) {

        // ── SecureRandom: never intercept ──
        if ("SecureRandom".equals(type)) {
            return null;
        }

        // ── Cipher transformation tracking ──
        // JCA tries the full transformation first ("AES/ECB/PKCS5Padding")
        // before the base algorithm ("AES").  Capture it for later policy
        // lookup, then return null so JCA falls through to base algorithm.
        if ("Cipher".equals(type) && algorithm.contains("/")) {
            PENDING_CIPHER_TRANSFORM.set(algorithm);
            return null;
        }

        // ── Re-entrancy guard ──
        int depth = DEPTH.get();
        if (depth > 0) {
            return null;
        }

        DEPTH.set(depth + 1);
        try {
            Provider bcfips = bcfipsInstance;
            if (bcfips == null) {
                bcfips = autoInitBcfips();
                if (bcfips == null) return null;
            }

            // ── BCFIPS probe: is this algorithm FIPS-approved? ──
            boolean fipsApproved = bcfips.getService(type, algorithm) != null;

            if (fipsApproved) {
                // BCFIPS recognises the algorithm - wrap for policy check
                return new AuditService(this, type, algorithm, true);
            }

            // BCFIPS does not recognise it - find a native provider
            for (Provider p : Security.getProviders()) {
                if (NAME.equals(p.getName()) || p == bcfips) continue;
                if (p.getService(type, algorithm) != null) {
                    return new AuditService(this, type, algorithm, false);
                }
            }

            return null;   // no provider supports it at all
        } finally {
            DEPTH.set(depth);
        }
    }

    // ── AuditService ───────────────────────────────────────────────────

    static final class AuditService extends Provider.Service {

        /** True when BCFIPS recognises the algorithm (FIPS-approved). */
        private final boolean fipsApproved;

        AuditService(Provider provider, String type, String algorithm,
                     boolean fipsApproved) {
            super(provider, type, algorithm, "(native-delegation)",
                    List.of(), null);
            this.fipsApproved = fipsApproved;
        }

        @Override
        public Object newInstance(Object constructorParameter)
                throws NoSuchAlgorithmException {

            int depth = DEPTH.get();
            DEPTH.set(depth + 1);
            try {
                // Retrieve cipher transformation captured in getService()
                String fullTransform = PENDING_CIPHER_TRANSFORM.get();
                PENDING_CIPHER_TRANSFORM.remove();

                // ── Layer 1: BCFIPS oracle ──
                if (!fipsApproved) {
                    String displayAlgo = fullTransform != null
                            ? fullTransform : getAlgorithm();
                    logAudit("DISALLOWED", getType(), displayAlgo,
                            "Algorithm not available in BCFIPS approved-only mode");
                    return delegateToNative(getType(), getAlgorithm(),
                            constructorParameter);
                }

                // ── Layer 2: Policy file ──
                String mode    = null;
                String padding = null;
                if (fullTransform != null) {
                    String[] parts = fullTransform.split("/");
                    if (parts.length >= 2) mode    = parts[1];
                    if (parts.length >= 3) padding = parts[2];
                }

                FipsPolicy.PolicyResult result =
                        policy().lookup(getType(), getAlgorithm(), mode, padding);

                if (result.classification() != FipsPolicy.Classification.APPROVED) {
                    String label = result.classification().name();
                    String algo  = fullTransform != null
                            ? fullTransform : getAlgorithm();
                    String reason = result.reason() != null
                            ? result.reason()
                            : label + " per fips-policy.properties";
                    logAudit(label, getType(), algo, reason);
                    return delegateToNative(getType(), getAlgorithm(),
                            constructorParameter);
                }

                // APPROVED - silent delegation, no audit entry
                return delegateToNativeSilent(getType(), getAlgorithm(),
                        constructorParameter);

            } finally {
                DEPTH.set(depth);
                PENDING_CIPHER_TRANSFORM.remove();   // always clean up
            }
        }

        // ── Audit logging ──────────────────────────────────────────────

        static void logAudit(String classification, String type,
                             String algorithm, String reason) {
            Logger log = auditLogger();
            StackTraceElement[] frames = Thread.currentThread().getStackTrace();
            StringBuilder sb = new StringBuilder();
            sb.append("FIPS AUDIT - ").append(classification).append('\n');
            sb.append("  Timestamp : ").append(Instant.now()).append('\n');
            sb.append("  JCA type  : ").append(type).append('\n');
            sb.append("  Algorithm : ").append(algorithm).append('\n');
            sb.append("  Reason    : ").append(reason).append('\n');
            sb.append("  Caller stack (application frames):\n");
            int printed = 0;
            int limit = stackDepth > 0 ? stackDepth : 20;
            for (StackTraceElement f : frames) {
                String cls = f.getClassName();
                if (cls.startsWith("java.") || cls.startsWith("javax.")
                        || cls.startsWith("jdk.") || cls.startsWith("sun.")
                        || cls.startsWith("com.demo.fips.audit.")) continue;
                sb.append("    at ").append(f).append('\n');
                if (++printed >= limit) {
                    sb.append("    ... (truncated)\n");
                    break;
                }
            }
            log.warning(sb.toString());
        }

        // ── Native delegation (with audit log of target) ──────────────

        private static Object delegateToNative(String type, String algorithm,
                Object param) throws NoSuchAlgorithmException {
            List<String> tried = new ArrayList<>();
            for (Provider p : Security.getProviders()) {
                String n = p.getName();
                if (NAME.equals(n) || "BCFIPS".equals(n)) continue;
                Provider.Service svc = p.getService(type, algorithm);
                if (svc == null) continue;
                try {
                    Object instance = svc.newInstance(param);
                    auditLogger().info("  -> delegated " + type + "/"
                            + algorithm + " to [" + n + "]");
                    return instance;
                } catch (Exception ex) {
                    tried.add(n + "(" + ex.getMessage() + ")");
                }
            }
            throw new NoSuchAlgorithmException(
                    "No provider supports " + type + "/" + algorithm
                    + "; tried: " + tried);
        }

        /**
         * Silent delegation &mdash; no audit log entry.
         * Used for FIPS-approved algorithms with no policy concerns.
         */
        private static Object delegateToNativeSilent(String type,
                String algorithm, Object param)
                throws NoSuchAlgorithmException {
            int depth = DEPTH.get();
            DEPTH.set(depth + 1);
            try {
                for (Provider p : Security.getProviders()) {
                    String n = p.getName();
                    if (NAME.equals(n) || "BCFIPS".equals(n)) continue;
                    Provider.Service svc = p.getService(type, algorithm);
                    if (svc == null) continue;
                    try {
                        return svc.newInstance(param);
                    } catch (Exception ignored) { }
                }
            } finally {
                DEPTH.set(depth);
            }
            throw new NoSuchAlgorithmException(
                    "No native provider supports " + type + "/" + algorithm);
        }
    }

    // ── Log formatter ──────────────────────────────────────────────────

    private static final class PlainFormatter extends Formatter {
        @Override
        public String format(LogRecord r) { return r.getMessage() + "\n"; }
    }
}
