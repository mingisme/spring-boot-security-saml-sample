package com.vdenotaris.spring.boot.security.saml.web.config;


import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@Order(30)
public class TenantRoutSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/ensso/idp/*").authorizeRequests().anyRequest().authenticated().and().addFilterBefore(tenantRoutFilter(), ChannelProcessingFilter.class);
    }

    private Filter tenantRoutFilter() {

        return new GenericFilterBean() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

                HttpServletRequest request = (HttpServletRequest) servletRequest;
                String requestURI = request.getRequestURI();
                if (requestURI.endsWith("/")) {
                    requestURI = requestURI.substring(0, requestURI.length() - 1);
                }
                int idpIndex = requestURI.lastIndexOf("/");
                String idp = requestURI.substring(idpIndex + 1);
                String path = null;

                //TODO: read idp provider list from configuration table
                if ("kc".equals(idp)) {
                    path = "/saml/login?idp=http://localhost:8081/auth/realms/demo";
                } else if ("aad".equals(idp)) {
                    path = "/oauth2/authorization/" + idp;
                } else {
                    throw new RuntimeException("Invalid idp_hint");
                }
                ((HttpServletResponse) servletResponse).sendRedirect(path);
            }
        };
    }
}
