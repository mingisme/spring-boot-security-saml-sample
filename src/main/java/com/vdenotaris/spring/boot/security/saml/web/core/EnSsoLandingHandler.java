package com.vdenotaris.spring.boot.security.saml.web.core;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface EnSsoLandingHandler {
    void handle(HttpServletRequest request, HttpServletResponse response, EnSsoAuthenticationToken authentication);
}
