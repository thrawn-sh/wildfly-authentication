/**
 * Copyright (C) 2016 shadowhunt (dev@shadowhunt.de)
 *
 * This file is part of Shadowhunt Wildfly Authentication.
 *
 * Shadowhunt Wildfly Authentication is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shadowhunt Wildfly Authentication is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Shadowhunt Wildfly Authentication. If not, see http://www.gnu.org/licenses/ .
 */
package de.shadowhunt.security.auth.spi;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class Password {

    public static final int DEFAULT_ITERATIONS = 25_000;

    public static final int DEFAULT_SALT_LENGTH = 16;

    public static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA512";

    private static final int INDEX_ITERATIONS;

    private static final int INDEX_PASSWORD;

    private static final int INDEX_SALT;

    public static final int PASSWORD_BITS = 512;

    private static final int VALUES_LENGTH;

    static {
        int values = 0;
        INDEX_PASSWORD = values++;
        INDEX_SALT = values++;
        INDEX_ITERATIONS = values++;
        VALUES_LENGTH = values;
    }

    public static Password create(final char[] clearText) {
        return create(clearText, new SecureRandom(), DEFAULT_SALT_LENGTH, DEFAULT_ITERATIONS);
    }

    public static Password create(final char[] clearText, final Random random, final int saltLength, final int iterations) {
        final byte[] salt = new byte[saltLength];
        random.nextBytes(salt);
        final byte[] passwordHash = hash(clearText, salt, iterations, PASSWORD_BITS);
        return new Password(passwordHash, salt, iterations);
    }

    static byte[] hash(final char[] passwordClearText, final byte[] salt, final int iterations, final int length) {
        final KeySpec keySpecification = new PBEKeySpec(passwordClearText, salt, iterations, length);
        try {
            final SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            final SecretKey secretKey = factory.generateSecret(keySpecification);
            final byte[] encoded = secretKey.getEncoded();
            if (encoded == null) {
                throw new SecurityException("can not hash password");
            }
            return encoded;
        } catch (final NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new SecurityException("can not hash password", e);
        }
    }

    public static Password parse(final String input) {
        final String[] values = input.split(":");
        if (values.length != VALUES_LENGTH) {
            throw new IllegalArgumentException("input does not contain " + VALUES_LENGTH + " parts, but " + values.length);
        }

        final String passwordBase64 = values[INDEX_PASSWORD];
        final String saltBase64 = values[INDEX_SALT];
        final String iterationsString = values[INDEX_ITERATIONS];

        final Decoder decoder = Base64.getDecoder();
        final byte[] passwordHash = decoder.decode(passwordBase64);
        final byte[] salt = decoder.decode(saltBase64);
        final int iterations = Integer.parseInt(iterationsString);
        if (iterations <= 0) {
            throw new IllegalArgumentException("iterations must be greater equal 0");
        }

        return new Password(passwordHash, salt, iterations);
    }

    static boolean slowEquals(final byte[] a, final byte[] b) {
        int diff = a.length ^ b.length;
        for (int i = 0; (i < a.length) && (i < b.length); i++) {
            diff |= a[i] ^ b[i];
        }
        return (diff == 0);
    }

    private final int iterations;

    private final byte[] passwordHash;

    private final byte[] salt;

    Password(final byte[] passwordHash, final byte[] salt, final int iterations) {
        this.passwordHash = passwordHash;
        this.salt = salt;
        this.iterations = iterations;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Password other = (Password) obj;
        if (iterations != other.iterations) {
            return false;
        }
        if (!Arrays.equals(passwordHash, other.passwordHash)) {
            return false;
        }
        if (!Arrays.equals(salt, other.salt)) {
            return false;
        }
        return true;
    }

    public String generateString() {
        final StringBuilder sb = new StringBuilder();
        final Encoder encoder = Base64.getEncoder();

        final byte[] passwordHashBase64 = encoder.encode(passwordHash);
        sb.append(new String(passwordHashBase64, StandardCharsets.UTF_8));
        sb.append(':');

        final byte[] saltBase64 = encoder.encode(salt);
        sb.append(new String(saltBase64, StandardCharsets.UTF_8));
        sb.append(':');

        sb.append(iterations);

        return sb.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + iterations;
        result = prime * result + Arrays.hashCode(passwordHash);
        result = prime * result + Arrays.hashCode(salt);
        return result;
    }

    public boolean matches(final char[] clearText) {
        final byte[] createHash = hash(clearText, salt, iterations, PASSWORD_BITS);
        return slowEquals(createHash, passwordHash);
    }

    @Override
    public String toString() {
        return "Password [passwordHash=" + Arrays.toString(passwordHash) + ", salt=" + Arrays.toString(salt) + ", iterations=" + iterations + "]";
    }
}
