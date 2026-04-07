package com.wallet.secure.common.util;

import lombok.extern.java.Log;

/**
 * Utility class for sanitizing user-controlled values before logging
 * Why this exists:
 * Log Injection (OWASP A09) - an attacker can include newline characters
 * In user-controlled input (email, URI, username) to forge fake log lines.
 *
 * Example attack without sanitization:
 *  Email: "test@test.com\n[WARN] Admin account compromised"
 *  Log output:
 *      [INFO] Login attempt: test@test.com
 *      [WARN] Admin account compromised <- attacker wrote this
 *
 * Example with sanitization:
 *  Log output:
 *      [INFO] Login attempt: test@test.com_[WARN] Admin account compromised -> one line, clearly malformed, no deception
 *
 * Why a static utility class and not a @Service:
 * -> No state, no dependencies - no reason to be a Spring bean
 * -> Callable from anywhere without injection
 * -> Consistent with Java standard library conventions (Math, Collections)
 * -> Easier to test - plain Java, no Spring context needed
 *
 * OWASP A09: Security Logging and Monitoring Failures
 */
public final class LogSanitizer {

    /**
     * Private constructor - this class is never instantiated.
     * All methods are static.
     */
    private LogSanitizer() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Sanitizes a user-controlled value for safe inclusion in log messages.
     *
     * Replaces with '_':
     * - ISO control characters (includes \n, \r, \t and all control codes 0-31, 127)
     * - Unicode line separator \u2028 (treated as newline by some log parsers)
     * - Unicode paragraph separator \u2029 (same risk)
     *
     * Why replace with '_' instead of removing:
     * Removing characters changes the length and can hide the injection attempt.
     * Replacing with '_' preserves the structure and makes the attack visible.
     *
     * @param value user-controlled string to sanitize (email, URI, username...)
     * @return sanitized string safe for logging, or "null" if value is null
     */
    public static String sanitize(String value) {

        if (value == null) return "null";

        StringBuilder sanitize = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (Character.isISOControl(ch)
                    || ch == '\u2028'
                    || ch == '\u2029') {
                sanitize.append('_');
            } else {
                sanitize.append(ch);
            }
        }
        return sanitize.toString();
    }
}