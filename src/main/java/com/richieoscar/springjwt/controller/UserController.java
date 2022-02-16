package com.richieoscar.springjwt.controller;

import com.richieoscar.springjwt.collection.User;
import com.richieoscar.springjwt.dto.RegistrationRequest;
import com.richieoscar.springjwt.exception.BadRequestException;
import com.richieoscar.springjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/user")
public class UserController {
    private UserRepository repository;
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public UserController(UserRepository repository, BCryptPasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }


    @PostMapping("/sign-up")
    public User signUp(@RequestBody RegistrationRequest request) {
        if (request.getUsername().isEmpty() || request.getPassword().isEmpty()) {
            throw new BadRequestException();
        }
        User user = new User();
        user.setName(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        repository.save(user);
        return user;
    }
}
