package com.vdenotaris.spring.boot.security.saml.web.core;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OIDCLogoutFilter extends LogoutFilter {

    /**
     * URL this filter processes
     */
    public static final String FILTER_URL = "/ensso/logout";


    public OIDCLogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler... handlers) {
        super(logoutSuccessHandler, handlers);
        this.setFilterProcessesUrl(FILTER_URL);
    }

    @Override
    protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
        //TODO: check idp and url match
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication instanceof  EnSsoAuthenticationToken) {
            EnSsoAuthenticationToken authn = (EnSsoAuthenticationToken) authentication;
            String idp = authn.getIdp();
            return super.requiresLogout(request, response) && "aad".equals(idp);
        }
        return false;
    }
}
