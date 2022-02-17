package com.richieoscar.springjwt.controller;

import com.richieoscar.springjwt.collection.AppUser;
import com.richieoscar.springjwt.dto.RegistrationRequest;
import com.richieoscar.springjwt.exception.BadRequestException;
import com.richieoscar.springjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

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
    public AppUser signUp(@RequestBody RegistrationRequest request) {
        if (request.getUsername().isEmpty() || request.getPassword().isEmpty()) {
            throw new BadRequestException();
        }
        AppUser appUser = new AppUser();
        appUser.setUsername(request.getUsername());
        appUser.setPassword(passwordEncoder.encode(request.getPassword()));
        repository.save(appUser);
        return appUser;
    }

    @GetMapping("/user/{username}")
    public AppUser getUser(@PathVariable("username") String username) {
        Optional<AppUser> user = repository.findByUsername(username);
        if(user.isPresent()){
            return user.get();
        }
        else throw new IllegalStateException("User not found");
    }

    @DeleteMapping("/delete")
    public String deleteAll() {
        repository.deleteAll();
        return "Users Deleted";
    }
}
