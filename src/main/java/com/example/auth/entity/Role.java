package com.example.auth.entity;

public class Role {
    long id;
    String name;

    public Role(long id, String name) {
        this.id = id;
        this.name = name;
    }

    public long getId() {
        return this.id;
    }

    public String getName() {
        return this.name;
    }
}
