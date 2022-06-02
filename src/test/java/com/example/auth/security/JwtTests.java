package com.example.auth.security;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class JwtTests {
    @Test
    public void jwtTest() throws Exception {
        String token = Jwt.createJWT("user name");
        String name = Jwt.decodeJWT(token);
        assertEquals(name, "user name");
    }
}
