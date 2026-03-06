package com.securecampus.ids.controller;

import com.securecampus.ids.entity.User;
import com.securecampus.ids.service.UserService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    // Create new user
    @PostMapping
    public User createUser(@RequestBody User user) {
        return userService.saveUser(user);
    }
    @GetMapping("/test")
    public String test() {
        return "Authenticated successfully";
    }

}
