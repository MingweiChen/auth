package com.example.auth.controller;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.example.auth.security.Jwt.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class AuthControllerTest {
    AuthController controller;

    @Before
    public void init() {
        controller = new AuthController();
    }

    @After
    public void cleanup() {
        AuthController.userRoleMap.clear();
        AuthController.roleIdMap.clear();
        AuthController.roleNameMap.clear();
        AuthController.userNameMap.clear();
        AuthController.userIdCounter.set(0L);
        AuthController.roleIdCounter.set(0L);
    }

    @Test
    public void createUserAndDeleteUserTest() throws Exception{
        controller.handleRequest(buildPayload("create_user", "u1", "password","",""));
        assertEquals(AuthController.userNameMap.containsKey("u1"), true);
        controller.handleRequest(buildPayload("delete_user", "u1", "","",""));
        assertEquals(AuthController.userNameMap.containsKey("u1"), false);
    }

    @Test
    public void createRoleAndDeleteRoleTest() throws Exception{
        controller.handleRequest(buildPayload("create_role", "", "","r1",""));
        assertEquals(AuthController.roleNameMap.containsKey("r1"), true);
        assertEquals(AuthController.roleIdMap.containsKey(1L), true);
        controller.handleRequest(buildPayload("delete_role", "", "","r1",""));
        assertEquals(AuthController.userNameMap.containsKey("r1"), false);
        assertEquals(AuthController.roleIdMap.containsKey(1L), false);
    }

    @Test
    public void createUserAndRole_then_addRoleToUser() throws Exception{
        controller.handleRequest(buildPayload("create_user", "u1", "password","r1",""));
        controller.handleRequest(buildPayload("create_role", "", "","r1",""));
        controller.handleRequest(buildPayload("add_role_to_user", "u1", "","r1",""));
        assertEquals(AuthController.userRoleMap.get("u1").size(), 1);
        assertEquals(AuthController.userRoleMap.get("u1").contains(1L), true);
    }

    @Test
    public void authenticateUser_then_checkRole() throws Exception{
        controller.handleRequest(buildPayload("create_user", "u1", "password","r1",""));
        controller.handleRequest(buildPayload("create_role", "", "","r1",""));
        controller.handleRequest(buildPayload("create_role", "", "","r2",""));
        controller.handleRequest(buildPayload("add_role_to_user", "u1", "","r1",""));
        String token = controller.handleRequest(
                buildPayload("authenticate", "u1", "password", "", "")).toString();
        String res1 = controller.handleRequest(
                buildPayload("check_role", "", "", "r1", token)).toString().toString();
        String res2 = controller.handleRequest(
                buildPayload("check_role", "", "", "r2", token)).toString().toString();
        assertEquals(res1, "true");
        assertEquals(res2, "false");
    }

    @Test
    public void authenticateUser_then_allRoles() throws Exception{
        controller.handleRequest(buildPayload("create_user", "u1", "password","r1",""));
        controller.handleRequest(buildPayload("create_role", "", "","r1",""));
        controller.handleRequest(buildPayload("create_role", "", "","r2",""));
        String token = controller.handleRequest(
                buildPayload("authenticate", "u1", "password", "", "")).toString();
        String res1 = controller.handleRequest(
                buildPayload("all_roles", "", "", "r1", token)).toString().toString();
        controller.handleRequest(buildPayload("add_role_to_user", "u1", "","r1",""));
        String res2 = controller.handleRequest(
                buildPayload("all_roles", "", "", "r2", token)).toString().toString();
        assertEquals(res1, "[]");
        assertEquals(res2, "[r1]");
    }

    @Test
    public void authenticateUser_then_invalidate() throws Exception{
        controller.handleRequest(buildPayload("create_user", "u1", "password","r1",""));
        String token = controller.handleRequest(
                buildPayload("authenticate", "u1", "password", "", "")).toString();
        assertEquals(AuthController.userNameMap.get("u1").getToken().length() > 0, true);
        controller.handleRequest(
                buildPayload("invalidate", "", "", "", token));
        assertEquals(AuthController.userNameMap.get("u1").getToken().length(), 0);
    }

    @Test
    public void expiredTokenUsed() throws Exception{
        controller.handleRequest(buildPayload("create_user", "u1", "password","r1",""));
        controller.handleRequest(
                buildPayload("authenticate", "u1", "password", "", "")).toString();
        String expiredToken = buildToken("u1",  System.currentTimeMillis() -  3L * 60L * 60L * 1000L);
        assertThrows(ExpiredJwtException.class, () -> {
            controller.handleRequest(
                    buildPayload("all_roles", "", "", "r2", expiredToken));
        });
    }

    @Test
    public void invalidatedTokenUsed() throws Exception{
        controller.handleRequest(buildPayload("create_user", "u1", "password","r1",""));
        String token = controller.handleRequest(
                buildPayload("authenticate", "u1", "password", "", "")).toString();
        controller.handleRequest(
                buildPayload("invalidate", "", "", "", token));
        assertThrows(IllegalArgumentException.class, () -> {
            controller.handleRequest(
                    buildPayload("all_roles", "", "", "r2", token));
        });
    }

    Map<String, Object>[] buildPayload(String action, String userName, String password, String roleName, String token) {
        Map<String, Object> map = new HashMap<>();
        map.put("action", action);
        map.put("userName", userName);
        map.put("password", password);
        map.put("roleName", roleName);
        map.put("token", token);
        return new Map[] {map};
    }

    String buildToken(String userName, long nowMillis) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userName", userName);
        JwtBuilder builder = Jwts.builder()
                .setClaims(claims)
                .signWith(KEY)
                .setExpiration(new Date(nowMillis + TTL_MILLIS));

        return builder.compact();
    }
}
