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

import java.util.Random;

import org.junit.Assert;
import org.junit.Test;

public class PasswordTest {

    private static final byte[] HASH = new byte[] { -57, 25, -99, -81, -69, 37, 34, 54, //
            -46, 51, 3, -99, 47, 41, 113, 52, //
            32, -95, 114, 71, -19, 77, -30, 30, //
            34, 43, -46, 8, 24, -15, 27, 95, //
            29, -22, -8, 75, 75, 110, 24, 86, //
            85, 29, -80, 121, 88, 39, -102, 30, //
            5, -39, -59, -106, 56, -120, -103, 116, //
            117, -107, 1, -124, -81, -2, -29, 24 };

    private static final byte[] SALT = new byte[] { 96, -76, 32, -69, 56, 81, -39, -44, 122, -53, -109, 61, -66, 112, 57, -101 };

    private static final String STRING_REPRERSENTATION = "xxmdr7slIjbSMwOdLylxNCChckftTeIeIivSCBjxG18d6vhLS24YVlUdsHlYJ5oeBdnFljiImXR1lQGEr/7jGA==:YLQguzhR2dR6y5M9vnA5mw==:25000";

    @Test
    public void createRandomTest() throws Exception {
        final char[] clearText = "test".toCharArray();
        final Password password = Password.create(clearText);
        Assert.assertNotNull("must not be null", password);
        Assert.assertTrue("passwords must match", password.matches(clearText));
    }

    @Test
    public void createTest() throws Exception {
        final char[] clearText = "test".toCharArray();
        final Password actual = Password.create(clearText, new Random(0L), Password.DEFAULT_SALT_LENGTH, Password.DEFAULT_ITERATIONS);
        Assert.assertNotNull("must not be null", actual);

        final Password expected = new Password(HASH, SALT, Password.DEFAULT_ITERATIONS);
        Assert.assertEquals("passwords must match", actual, expected);
    }

    @Test
    public void generateStringTest() throws Exception {
        final Password password = new Password(HASH, SALT, Password.DEFAULT_ITERATIONS);
        Assert.assertEquals("string must match", STRING_REPRERSENTATION, password.generateString());
    }

    @Test(expected = IllegalArgumentException.class)
    public void hashEmptySaltTest() throws Exception {
        final char[] clearText = "test".toCharArray();
        Password.hash(clearText, new byte[0], Password.DEFAULT_ITERATIONS, Password.PASSWORD_BITS);
        Assert.fail("must not complete");
    }

    @Test(expected = NullPointerException.class)
    public void hashNullSaltTest() throws Exception {
        final char[] clearText = "test".toCharArray();
        Password.hash(clearText, null, Password.DEFAULT_ITERATIONS, Password.PASSWORD_BITS);
        Assert.fail("must not complete");
    }

    @Test
    public void hashTest() throws Exception {
        final char[] clearText = "test".toCharArray();
        final byte[] actual = Password.hash(clearText, SALT, Password.DEFAULT_ITERATIONS, Password.PASSWORD_BITS);
        Assert.assertArrayEquals("arrays must match", actual, HASH);
    }

    @Test(expected = IllegalArgumentException.class)
    public void hashWrongIterationsTest() throws Exception {
        final char[] clearText = "test".toCharArray();
        Password.hash(clearText, SALT, 0, Password.PASSWORD_BITS);
        Assert.fail("must not complete");
    }

    @Test(expected = IllegalArgumentException.class)
    public void hashWrongKeyLengthTest() throws Exception {
        final char[] clearText = "test".toCharArray();
        Password.hash(clearText, SALT, Password.DEFAULT_ITERATIONS, 0);
        Assert.fail("must not complete");
    }

    @Test(expected = IllegalArgumentException.class)
    public void parse0IterationsTest() throws Exception {
        Password.parse("IA==:IA==:0");
        Assert.fail("must not complete");
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseAdditionalFieldsTest() throws Exception {
        Password.parse("a:b:c:d");
        Assert.fail("must not complete");
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseMissingFieldsTest() throws Exception {
        Password.parse("a:b");
        Assert.fail("must not complete");
    }

    @Test(expected = NullPointerException.class)
    public void parseNullPasswordTest() throws Exception {
        Password.parse(null);
        Assert.fail("must not complete");
    }

    @Test
    public void parseTest() throws Exception {
        final Password actual = Password.parse(STRING_REPRERSENTATION);
        final Password expected = new Password(HASH, SALT, Password.DEFAULT_ITERATIONS);
        Assert.assertEquals("passwords must match", actual, expected);
    }

    @Test
    public void slowEqualsTest() throws Exception {
        final byte[] a = new byte[] { 1, 2, 3, 4, 5 };
        final byte[] b = new byte[] { 6, 7, 8, 9, 0 };
        final byte[] empty = new byte[0];

        Assert.assertTrue("arrays must equal", Password.slowEquals(empty, empty));
        Assert.assertTrue("arrays must equal", Password.slowEquals(a, a));
        Assert.assertFalse("arrays must not equal", Password.slowEquals(a, b));
        Assert.assertFalse("arrays must not equal", Password.slowEquals(b, a));
    }
}
