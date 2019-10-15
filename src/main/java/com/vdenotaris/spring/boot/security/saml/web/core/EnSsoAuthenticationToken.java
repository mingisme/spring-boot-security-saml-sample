package com.vdenotaris.spring.boot.security.saml.web.core;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class EnSsoAuthenticationToken extends AbstractAuthenticationToken {

    private final EnSsoUser principal;
    private final Object credentials;
    private final String idp;
    private final Object origin;

    public EnSsoAuthenticationToken(EnSsoUser principal, Object credentials, Collection<? extends GrantedAuthority> authorities, String idp, Object origin) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.idp = idp;
        this.origin = origin;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public EnSsoUser getPrincipal() {
        return principal;
    }

    public Object getOrigin() {
        return origin;
    }

    public String getIdp() {
        return idp;
    }
}
