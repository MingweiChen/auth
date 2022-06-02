package com.example.auth.security;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CryptoTests {
    Crypto crypto = new Crypto();

    @Test
    public void cryptoTest() throws Exception {
        String password = "12345678";
        String encode = crypto.encrypt(password);
        String decode = crypto.decrypt(encode);
        assertEquals(password, decode);
    }
}
