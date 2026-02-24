package com.demo.fips.audit;

import java.io.InputStream;
import java.util.Properties;

/**
 * Loads and queries the configurable FIPS policy file ({@code fips-policy.properties}).
 *
 * <p>The policy file lets operators flag JCA algorithm/mode/padding combinations
 * as {@link Classification#WEAK WEAK} or {@link Classification#DISALLOWED DISALLOWED}
 * independently of what BCFIPS itself accepts.  This covers cases where an
 * algorithm is technically FIPS-approved but operationally deprecated or
 * insecure (e.g.&nbsp;AES/ECB, SHA-1, 3DES).</p>
 *
 * <p>Lookup uses hierarchical key matching &mdash; the most specific key wins:</p>
 * <ol>
 *   <li>{@code Type.Algorithm.Mode.Padding}</li>
 *   <li>{@code Type.Algorithm.Mode}</li>
 *   <li>{@code Type.Algorithm}</li>
 * </ol>
 *
 * <p>If no rule matches, the result is {@link Classification#APPROVED APPROVED}.</p>
 */
final class FipsPolicy {

    // ── Classification ─────────────────────────────────────────────────

    enum Classification { APPROVED, WEAK, DISALLOWED }

    // ── Result ─────────────────────────────────────────────────────────

    record PolicyResult(Classification classification, String reason) {
        static final PolicyResult DEFAULT_APPROVED =
                new PolicyResult(Classification.APPROVED, null);
    }

    // ── Internals ──────────────────────────────────────────────────────

    private static final String RESOURCE = "/fips-policy.properties";

    private final Properties rules = new Properties();

    FipsPolicy() {
        try (InputStream is = getClass().getResourceAsStream(RESOURCE)) {
            if (is != null) {
                rules.load(is);
                System.err.println("[FipsAudit] Policy loaded: "
                        + rules.size() + " rules from " + RESOURCE);
            } else {
                System.err.println("[FipsAudit] WARNING: " + RESOURCE
                        + " not found on classpath — no policy rules active");
            }
        } catch (Exception e) {
            System.err.println("[FipsAudit] WARNING: cannot load "
                    + RESOURCE + ": " + e.getMessage());
        }
    }

    // ── Lookup ─────────────────────────────────────────────────────────

    /**
     * Look up the policy classification for a JCA request.
     *
     * @param type      JCA service type (e.g. "Cipher", "MessageDigest")
     * @param algorithm base algorithm name (e.g. "AES", "SHA-1")
     * @param mode      cipher mode or {@code null} (e.g. "ECB", "CBC")
     * @param padding   padding scheme or {@code null} (e.g. "PKCS5Padding")
     * @return the most specific matching rule, or {@link PolicyResult#DEFAULT_APPROVED}
     */
    PolicyResult lookup(String type, String algorithm, String mode, String padding) {
        // Most specific first
        if (mode != null && padding != null) {
            PolicyResult r = tryKey(type + "." + algorithm + "." + mode + "." + padding);
            if (r != null) return r;
        }
        if (mode != null) {
            PolicyResult r = tryKey(type + "." + algorithm + "." + mode);
            if (r != null) return r;
        }
        PolicyResult r = tryKey(type + "." + algorithm);
        return r != null ? r : PolicyResult.DEFAULT_APPROVED;
    }

    // ── Helpers ────────────────────────────────────────────────────────

    private PolicyResult tryKey(String key) {
        String value = rules.getProperty(key);
        if (value == null) return null;
        return parse(value.trim());
    }

    private static PolicyResult parse(String value) {
        int pipe = value.indexOf('|');
        String cls = (pipe < 0 ? value : value.substring(0, pipe)).trim().toUpperCase();
        String reason = pipe >= 0 ? value.substring(pipe + 1).trim() : null;

        Classification c = switch (cls) {
            case "WEAK"       -> Classification.WEAK;
            case "DISALLOWED" -> Classification.DISALLOWED;
            default           -> Classification.APPROVED;
        };
        return new PolicyResult(c, (reason != null && reason.isEmpty()) ? null : reason);
    }
}
