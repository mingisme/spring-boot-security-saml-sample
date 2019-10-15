package com.vdenotaris.spring.boot.security.saml.web.core;


import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.MultiValueMap;

import java.util.Collection;

public class EnSsoUser implements AuthenticatedPrincipal {

    private final Object origin;
    private final String userNameAttributeKey;
    private final String nickNameAttributeKey;
    private final String firstNameAttributeKey;
    private final String lastNameAttributeKey;
    private final String emailAttributeKey;
    private final String phoneAttributeKey;
    private final MultiValueMap<String,Object> attributes;
    private final Collection<? extends GrantedAuthority> authorities;

    public EnSsoUser(String userNameAttributeKey, String firstNameAttributeKey, String lastNameAttributeKey, String emailAttributeKey, String phoneAttributeKey, String nickNameAttributeKey, MultiValueMap<String, Object> attributes, Collection<? extends GrantedAuthority> authorities, Object origin) {
        this.firstNameAttributeKey = firstNameAttributeKey;
        this.lastNameAttributeKey = lastNameAttributeKey;
        this.emailAttributeKey = emailAttributeKey;
        this.phoneAttributeKey = phoneAttributeKey;
        this.nickNameAttributeKey = nickNameAttributeKey;
        this.origin = origin;
        this.userNameAttributeKey = userNameAttributeKey;
        this.attributes = attributes;
        this.authorities = authorities;
    }

    public String getPhone() {
        return (String)attributes.getFirst(phoneAttributeKey);
    }

    public String getEmail() {
        return (String)attributes.getFirst(emailAttributeKey);
    }

    public String getNickName() {
        return (String)attributes.getFirst(nickNameAttributeKey);
    }

    public String getLastName() {
        return (String)attributes.getFirst(lastNameAttributeKey);
    }

    public String getFirstName() {
        return (String)attributes.getFirst(firstNameAttributeKey);
    }

    public String getUserName() {
        return (String)attributes.getFirst(userNameAttributeKey);
    }

    public String getNickNameAttributeKey() {
        return nickNameAttributeKey;
    }

    @Override
    public String getName() {
        return (String)attributes.getFirst(userNameAttributeKey);
    }

    public MultiValueMap<String, Object> getAttributes() {
        return attributes;
    }

    public Object getOrigin() {
        return origin;
    }

    public String getUserNameAttributeKey() {
        return userNameAttributeKey;
    }

    public String getFirstNameAttributeKey() {
        return firstNameAttributeKey;
    }

    public String getLastNameAttributeKey() {
        return lastNameAttributeKey;
    }

    public String getEmailAttributeKey() {
        return emailAttributeKey;
    }

    public String getPhoneAttributeKey() {
        return phoneAttributeKey;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
}
