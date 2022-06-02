package com.example.auth.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Jwt {

    public static final Key KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    public static final long TTL_MILLIS = 2L * 60L * 60L * 1000L;

    public static String createJWT(String userName) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userName", userName);

        long nowMillis = System.currentTimeMillis();
        JwtBuilder builder = Jwts.builder()
                .setClaims(claims)
                .signWith(KEY)
                .setExpiration(new Date(nowMillis + TTL_MILLIS));

        return builder.compact();
    }

    public static String decodeJWT(String jwt) throws Exception {
        Object claims = Jwts.parserBuilder()
                .setSigningKey(KEY)
                .build()
                .parse(jwt).getBody();
        return ((Claims)claims).get("userName").toString();
    }
}
