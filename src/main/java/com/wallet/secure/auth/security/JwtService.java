package com.wallet.secure.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

/**
 * Handles all JWT operations: generate, validate, extract claims.
 *
 * WHY a dedicated service and not inline in AuthService:
 * Single Responsibility — AuthService handles business logic (login, logout).
 * JwtService handles only token mechanics.
 * Easier to test each in isolation.
 *
 * Reads JWT config from application.yml:
 *   jwt.secret          → signing key (from .env → GitHub Secrets)
 *   jwt.expiration      → access token lifetime (900000 ms = 15 min)
 *   jwt.refresh-expiration → refresh token lifetime (604800000 ms = 7 days)
 *   jwt.issuer          → "secure-wallet-api"
 *
 * OWASP A07: tokens are short-lived, signed and validated on every request.
 * OWASP A02: secret key loaded once at startup — never logged, never exposed.
 */
@Service
@Log4j2
public class JwtService {

    private final SecretKey signingKey;
    private final long expirationMs;
    private final long refreshExpirationMs;
    private final String issuer;

    /**
     * Constructor - Spring injects JWT properties from application.yml
     * The key is built ONCE at startup - not on every token operation
     * Why @value in constructor and not field injection:
     * -> Immutable fields (final) - safer, no risk of accidental mutation
     * -> Easier to test -  can pass values directly without Spring context
     *
     * @param secret raw secret string from JWT_SECRET env variable
     * @param expiration access token lifetime in milliseconds
     * @param refreshExp refresh token lifetime in milliseconds
     * @param issuer token issuer identifier
     */
    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration}") long expiration,
            @Value("${jwt.refresh-expiration}") long refreshExp,
            @Value("${jwt.issuer}") String issuer) {

        // Build the signing key from the secret string
        // Keys.hmacShaKeyFor requires minimum 32 bytes for HS256
        // Your JWT_SECRET generated with openssl rand -base64 64 is well above that
        this.signingKey = Keys.hmacShaKeyFor(
                secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expiration;
        this.refreshExpirationMs = refreshExp;
        this.issuer = issuer;
    }

    // ─── Token Generation ─────────────────────────────────────────────────────

    /**
     * Generates a short-lived access token (15 minutes).
     * Used after successful login or registration.
     *
     * Token structure (decoded payload):
     * {
     *   "sub": "angel@test.com",   ← subject = email
     *   "iss": "secure-wallet-api",← issuer
     *   "iat": 1711234567,          ← issued at
     *   "exp": 1711235467,          ← expires at (iat + 15 min)
     *   "type": "access"            ← custom claim to distinguish token types
     * }
     *
     * OWASP A07: short expiration limits damage if token is stolen.
     *
     * @param email the authenticated user's email (subject)
     * @return signed JWT string
     */
    public String generateAccessToken(String email) {
        return buildToken(email, expirationMs, "access");
    }

    /**
     * Generates a long-lived refresh token (7 days).
     * Used only at POST /auth/refresh to obtain a new access token.
     * Stored in DB — can be revoked on logout.
     *
     * OWASP A07: stored in DB so logout truly invalidates the session.
     *
     * @param email the authenticated user's email (subject)
     * @return signed JWT string
     */
    public String generateRefreshToken(String email) {
        return buildToken(email, refreshExpirationMs, "refresh");
    }

    /**
     * Internal token builder — shared logic for access and refresh tokens.
     * Both tokens use the same signing key and structure.
     * The "type" claim distinguishes them.
     */
    private String buildToken(String email, long lifetimeMs, String tokenType) {
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(lifetimeMs);

        return Jwts.builder()
                .subject(email)                     // who the token belongs to
                .issuer(issuer)                     // who issued it
                .issuedAt(Date.from(now))           // when it was created
                .expiration(Date.from(expiry))      // when it expires
                .claim("type", tokenType)           // "access" or "refresh"
                .signWith(signingKey)               // HMAC-SHA256 signature
                .compact();                         // serialize to string
    }

    // ─── Token Validation ─────────────────────────────────────────────────────

    /**
     * Validates a token and returns true if it is valid.
     *
     * Checks performed by JJWT automatically:
     * 1. Signature valid (not tampered)
     * 2. Not expired
     * 3. Issuer matches
     *
     * Additional check:
     * 4. Token type matches expected type ("access" or "refresh")
     *
     * Returns false (never throws) — caller decides what to do.
     * JwtAuthFilter uses this to decide whether to reject the request.
     *
     * OWASP A07: every request is re-validated — no trust without verification.
     *
     * @param token the raw JWT string (without "Bearer " prefix)
     * @param expectedType "access" or "refresh"
     * @return true if the token is valid and of the expected type
     */
    public boolean isTokenValid(String token, String expectedType) {
        try {
            Claims claims = extractAllClaims(token);

            // Verify token type — prevents using a refresh token as access token
            // OWASP A07: token type confusion attack prevention
            String tokenType = claims.get("type", String.class);
            return expectedType.equals(tokenType);

        } catch (ExpiredJwtException e) {
            log.debug("JWT expired");
            return false;
        } catch (JwtException e) {
            log.warn("Invalid JWT: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Convenience method — validates access token specifically.
     * Used by JwtAuthFilter on every incoming request.
     */
    public boolean isAccessTokenValid(String token) {
        return isTokenValid(token, "access");
    }

    /**
     * Convenience method — validates refresh token specifically.
     * Used by AuthService on POST /auth/refresh.
     */
    public boolean isRefreshTokenValid(String token) {
        return isTokenValid(token, "refresh");
    }

    // ─── Claims Extraction ────────────────────────────────────────────────────

    /**
     * Extracts the email (subject) from a token.
     * Called by JwtAuthFilter to identify the authenticated user.
     *
     * @param token raw JWT string
     * @return email stored in the "sub" claim
     * @throws JwtException if the token is invalid or expired
     */
    public String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Returns the access token lifetime in SECONDS (not milliseconds).
     * Used to populate AuthResponse.expiresIn for the client.
     * The client uses this to schedule a silent refresh before expiration.
     */
    public long getExpirationInSeconds() {
        return expirationMs / 1000;
    }

    /**
     * Returns the refresh token lifetime in MILLISECONDS.
     * Used by SessionService to calculate session.expiresAt.
     * The session must expire at exactly the same time as the refresh token.
     */
    public long getRefreshExpirationMs() {
        return refreshExpirationMs;
    }

    // ─── Private Helper ───────────────────────────────────────────────────────

    /**
     * Parses and verifies the token signature, then returns all claims.
     *
     * JJWT performs these checks automatically during parsing:
     * - Signature verification (tampering detection)
     * - Expiration check
     * - Issuer check (if configured)
     *
     * Throws JwtException subtypes if any check fails:
     * - ExpiredJwtException    → token is expired
     * - SignatureException     → signature does not match (tampered)
     * - MalformedJwtException  → not a valid JWT format
     * - UnsupportedJwtException→ algorithm or format not supported
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)          // verify signature
                .requireIssuer(issuer)           // verify issuer claim
                .build()
                .parseSignedClaims(token)        // parse + verify
                .getPayload();                   // return claims
    }
}