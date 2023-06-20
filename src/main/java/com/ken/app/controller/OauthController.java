package com.ken.app.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OauthController {

    @GetMapping("/")
    public String helloWorld(Authentication authentication) {
        return "Hello World";
    }
}
