package com.richieoscar.springjwt.security;

import com.richieoscar.springjwt.collection.AppUser;
import com.richieoscar.springjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    private UserRepository repository;

    @Autowired
    public UserDetailServiceImpl(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<AppUser> userOptional = repository.findByUsername(username);
        if (userOptional.isPresent()) {
            AppUser appUser = userOptional.get();
            return new org.springframework.security.core.userdetails.User(appUser.getUsername(), appUser.getPassword(), Collections.emptyList());
        } else throw new UsernameNotFoundException(String.format("User not found with this %", username));
    }
}
