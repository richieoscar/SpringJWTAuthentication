package com.richieoscar.springjwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.richieoscar.springjwt.collection.AppUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.richieoscar.springjwt.constants.SecurityConstants.*;

@Slf4j
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    @Autowired
    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            AppUser appUserCredentials = new ObjectMapper().readValue(request.getInputStream(), AppUser.class);
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(appUserCredentials.getUsername(), appUserCredentials.getPassword(), Collections.emptyList());
            Authentication authenticatedUser = authenticationManager.authenticate(token);
            return authenticatedUser;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        org.springframework.security.core.userdetails.User user = (org.springframework.security.core.userdetails.User) authResult.getPrincipal();
        String jwtToken = JWT.create()
                .withSubject(user.getUsername())
                .withIssuer(request.getRequestURL().toString())
                .withExpiresAt(new Date(System.currentTimeMillis() + SECURITY_TOKEN_EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(SECRET_KEY.getBytes()));
        log.info("Adding token to response head");
        response.addHeader(HEADER_STRING, TOKEN_PREFIX + jwtToken);
        Map<String, String> token = new HashMap<>();
        token.put(HEADER_STRING, TOKEN_PREFIX + jwtToken);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), token);
    }
}
