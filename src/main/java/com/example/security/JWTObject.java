package com.example.security;

import lombok.Getter;
import lombok.Setter;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

@Getter
@Setter
public class JWTObject {
    private String subject; //nome do usuario
    private Date issuedAt; //data de criação do token
    private Date expiration; //data de expiracao do token
    private List<String> roles; //perfis de acesso

    public void setRoles(String... roles){
        this.roles = Arrays.asList(roles);
    }
}
