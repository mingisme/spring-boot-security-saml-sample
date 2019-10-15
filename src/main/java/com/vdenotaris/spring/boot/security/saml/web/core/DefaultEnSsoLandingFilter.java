package com.vdenotaris.spring.boot.security.saml.web.core;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class DefaultEnSsoLandingFilter extends GenericFilterBean {

    private static final String FILTER_PATH = "/ensso/landing";

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        if(request.getRequestURI().endsWith(FILTER_PATH)) {
            servletResponse.setContentType("application/json");
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            ObjectMapper objectMapper = new ObjectMapper();
            String content = objectMapper.writeValueAsString(auth.getPrincipal());
            servletResponse.getWriter().write(content);
        }else{
            filterChain.doFilter(servletRequest,servletResponse);
        }

    }
}
