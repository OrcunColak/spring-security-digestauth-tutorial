package com.colak.springtutorial.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.MessageFormat;
import java.util.Collection;

@RestController
@RequestMapping("/api")
public class AccountController {

    // http://localhost:8080/api/account
    @GetMapping("/account")
    public ResponseEntity<String> getUserInfo() {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        var userData = MessageFormat.format("username:{0} - authorities:{1}", authentication.getName() ,authorities);

        return ResponseEntity.ok(userData);
    }

}
