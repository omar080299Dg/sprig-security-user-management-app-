package dev.niangfils.springsec.service;

import dev.niangfils.springsec.domain.Role;
import dev.niangfils.springsec.domain.User;

import java.util.List;

public interface UserService {

    User saveUser(User user);

    Role saveRole(Role role);

    void addRoleToUser(String username, String roleName);

    User getUser(String username);

    List<User> getAllUsers();
}
