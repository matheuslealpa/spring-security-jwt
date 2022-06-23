package com.example.controller;

import com.example.dtos.Login;
import com.example.dtos.Sessao;
import com.example.model.User;
import com.example.repository.UserRepository;
import com.example.security.JWTCreator;
import com.example.security.JWTObject;
import com.example.security.SecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
public class LoginController {
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private UserRepository repository;

    @PostMapping("/login")
    public Sessao logar(@RequestBody Login login){
        User user = repository.findByUsername(login.getUsername());
        if(user!=null){
            boolean passwordOk = encoder.matches(login.getPassword(), user.getPassword());
            if (!passwordOk){
                throw new RuntimeException("Senha inválida para login: " + login.getUsername());
            }
            Sessao sessao = new Sessao();
            sessao.setLogin(user.getUsername());

            JWTObject jwtObject = new JWTObject();
            jwtObject.setIssuedAt(new Date(System.currentTimeMillis()));
            jwtObject.setExpiration(new Date(System.currentTimeMillis() + SecurityConfig.EXPIRATION));
            jwtObject.setRoles(String.valueOf(user.getRoles()));
            sessao.setToken(JWTCreator.create(SecurityConfig.PREFIX, SecurityConfig.KEY, jwtObject));
            return sessao;
        }else{
            throw new RuntimeException("Erro ao tentar fazer login");
        }
    }
}
