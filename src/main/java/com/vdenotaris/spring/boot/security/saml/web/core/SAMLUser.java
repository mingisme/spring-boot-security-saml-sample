package com.vdenotaris.spring.boot.security.saml.web.core;


import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.MultiValueMap;

import java.util.Collection;

public class SAMLUser {

    private final String nameID;
    private final MultiValueMap<String,Object> attributes;
    private final Collection<? extends GrantedAuthority> authorities;

    public SAMLUser(String nameID, MultiValueMap<String, Object> attributes, Collection<? extends GrantedAuthority> authorities) {
        this.nameID = nameID;
        this.attributes = attributes;
        this.authorities = authorities;
    }

    public String getNameID() {
        return nameID;
    }

    public MultiValueMap<String, Object> getAttributes() {
        return attributes;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
}
