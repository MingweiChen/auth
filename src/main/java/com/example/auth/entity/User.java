package com.example.auth.entity;

public class User {

    long id;
    String name;
    String password;
    String token;

    public User(long id, String name, String password) {
        this.id = id;
        this.name = name;
        this.password = password;
        this.token = "";
    }

    public long getId() {
        return this.id;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getToken() {
        return this.token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
