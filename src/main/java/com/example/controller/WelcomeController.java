package com.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {
    @GetMapping
    public String Welcome(){
        return "Welcome to my Spring Boot Web API";
    }
    @GetMapping("/users")
    public String users(){
        return "Authorized user";
    }
    @GetMapping("/managers")
    public String managers(){
        return "Authorized managers";
    }

}
