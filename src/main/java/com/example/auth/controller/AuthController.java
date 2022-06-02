package com.example.auth.controller;

import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import com.example.auth.security.Crypto;
import com.example.auth.security.Jwt;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@RestController
public class AuthController {
    static final AtomicLong userIdCounter = new AtomicLong(0);
    static final AtomicLong roleIdCounter = new AtomicLong(0);

    static final ConcurrentHashMap<String, User> userNameMap = new ConcurrentHashMap();
    static final ConcurrentHashMap<Long, Role> roleIdMap = new ConcurrentHashMap();
    static final ConcurrentHashMap<String, Long> roleNameMap = new ConcurrentHashMap();
    static final ConcurrentHashMap<String, Set<Long>> userRoleMap = new ConcurrentHashMap();

    private Crypto crypto = new Crypto();

    @PostMapping("/auth")
    public Object handleRequest(@RequestBody Map<String, Object>[] payload) throws Exception{
        if(payload.length != 1 || !payload[0].containsKey("action"))
            throw new IllegalArgumentException("Invalid request.");

        String action = payload[0].get("action").toString();
        switch (action) {
            case "create_user":
                createUser(payload[0]);
                break;
            case "delete_user":
                deleteUser(payload[0]);
                break;
            case "create_role":
                createRole(payload[0]);
                break;
            case "delete_role":
                deleteRole(payload[0]);
                break;
            case "add_role_to_user":
                addRoleToUser(payload[0]);
                break;
            case "authenticate":
                return authenticate(payload[0]);
            case "invalidate":
                invalidate(payload[0]);
                break;
            case "check_role":
                return checkRole(payload[0]);
            case "all_roles":
                return allRoles(payload[0]);
            default:
                throw new IllegalArgumentException("Invalid action.");
        }
        return null;
    }

    public void createUser(Map<String, Object> payload) throws Exception {
        if (!payload.containsKey("userName") || !payload.containsKey("password")) {
            throw new IllegalArgumentException("The user name or password was not found in the request");
        }
        String userName = payload.get("userName").toString();
        String password = payload.get("password").toString();
        if (userNameMap.containsKey(userName)) {
            throw new IllegalArgumentException("The user had been created.");
        }

        Long userId = userIdCounter.addAndGet(1L);
        User user = new User(userId, userName, crypto.encrypt(password));
        userNameMap.put(userName, user);
    }

    public void deleteUser(Map<String, Object> payload) throws Exception {
        if (!payload.containsKey("userName")) {
            throw new IllegalArgumentException("The user name was not found in the request");
        }

        String userName = payload.get("userName").toString();

        if (!userNameMap.containsKey(userName)) {
            throw new IllegalArgumentException("The specified user didn't exist.");
        }
        userNameMap.remove(userName);
        if (userRoleMap.containsKey(userName)) {
            userRoleMap.remove(userName);
        }
    }

    public void createRole(Map<String, Object> payload) throws Exception {
        if (!payload.containsKey("roleName")) {
            throw new IllegalArgumentException("The role name was not found in the request.");
        }

        String roleName = payload.get("roleName").toString();

        if (roleNameMap.containsKey(roleName)) {
            throw new IllegalArgumentException("The role had been created.");
        }

        Long roleId = roleIdCounter.addAndGet(1L);;
        Role role = new Role(roleId, roleName);
        roleIdMap.put(roleId, role);
        roleNameMap.put(roleName, roleId);
    }

    public void deleteRole(Map<String, Object> payload) throws Exception {
        if (!payload.containsKey("roleName")) {
            throw new IllegalArgumentException("The role name was not found in the request.");
        }

        String roleName = payload.get("roleName").toString();

        if (!roleNameMap.containsKey(roleName)) {
            throw new Exception("The role didn't exist.");
        }
        long roleId =  roleNameMap.get(roleName);
        roleNameMap.remove(roleName);
        roleIdMap.remove(roleId);
    }

    public void addRoleToUser(Map<String, Object> payload) throws Exception {
        if (!payload.containsKey("userName") || !payload.containsKey("roleName")) {
            throw new IllegalArgumentException("The user name or role name was not found in the request.");
        }
        String userName = payload.get("userName").toString();
        String roleName = payload.get("roleName").toString();
        if (!roleNameMap.containsKey(roleName) || !userNameMap.containsKey(userName)) {
            throw new IllegalArgumentException("The user name or role name was invalid.");
        }
        long roleId = roleNameMap.get(roleName);
        if (!userRoleMap.containsKey(userName)) {
            userRoleMap.put(userName, new HashSet<>());
        }
        userRoleMap.get(userName).add(roleId);
    }

    public String authenticate(Map<String, Object> payload) throws Exception{
        if (!payload.containsKey("userName") || !payload.containsKey("password")) {
            throw new IllegalArgumentException("The user name or password was not found in the request");
        }
        String userName = payload.get("userName").toString();
        String password = payload.get("password").toString();

        if (!userNameMap.containsKey(userName)) {
            throw new Exception("The user name didn't exist.");
        }

        User user = userNameMap.get(userName);
        String token = Jwt.createJWT(userName);
        user.setToken(token);
        return token;

    }

    public void invalidate(Map<String, Object> payload) throws Exception{
        if (!payload.containsKey("token")) {
            throw new IllegalArgumentException("The token was not found in the request");
        }
        String token = payload.get("token").toString();

        String userName = Jwt.decodeJWT(token);
        if (!userNameMap.containsKey(userName)) {
            throw new IllegalArgumentException("the specified user was deleted.");
        }
        User user = userNameMap.get(userName);
        if (!user.getToken().equals(token)) {
            throw new IllegalArgumentException("the token was invalidated.");
        }
        user.setToken("");
    }

    public boolean checkRole(Map<String, Object> payload) throws Exception {
        if (!payload.containsKey("token") || !payload.containsKey("roleName") ) {
            throw new IllegalArgumentException("The token or role name was not found in the request");
        }
        String token = payload.get("token").toString();
        String roleName = payload.get("roleName").toString();
        if (!roleNameMap.containsKey(roleName)) {
            throw new IllegalArgumentException("The role was deleted.");
        }

        String userName = Jwt.decodeJWT(token);
        if (!userNameMap.containsKey(userName)) {
            throw new IllegalArgumentException("the specified user was deleted.");
        }

        User user = userNameMap.get(userName);
        if (!user.getToken().equals(token)) {
            throw new IllegalArgumentException("the token was invalidated.");
        }

        Long roleId = roleNameMap.get(roleName);
        if (userRoleMap.containsKey(userName) && userRoleMap.get(userName).contains(roleId)) {
            return true;
        }
        return false;
    }

    public String allRoles(Map<String, Object> payload) throws Exception {
        if (!payload.containsKey("token")) {
            throw new IllegalArgumentException("The token was not found in the request");
        }
        String token = payload.get("token").toString();
        String userName = Jwt.decodeJWT(token);
        if (!userNameMap.containsKey(userName)) {
            throw new IllegalArgumentException("the specified user was deleted.");
        }

        User user = userNameMap.get(userName);
        if (!user.getToken().equals(token)) {
            throw new IllegalArgumentException("the token was invalidated.");
        }

        if (!userRoleMap.containsKey(userName)) {
            return "[]";
        } else {
            Set<Long> roles = userRoleMap.get(userName);
            List<String> roleList = new LinkedList<>();
            for (Long roleId : roles) {
                if (roleIdMap.containsKey(roleId)) {
                    roleList.add(roleIdMap.get(roleId).getName());
                }
            }
            return roleList.toString();
        }

    }

    @ExceptionHandler({ IllegalArgumentException.class, ExpiredJwtException.class })
    public ResponseEntity<String> handleException(Exception e) {
        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
    }
}
