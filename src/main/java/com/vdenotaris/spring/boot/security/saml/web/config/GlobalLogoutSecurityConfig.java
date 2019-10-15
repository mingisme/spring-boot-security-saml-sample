package com.vdenotaris.spring.boot.security.saml.web.config;


import com.vdenotaris.spring.boot.security.saml.web.core.OIDCLogoutFilter;
import com.vdenotaris.spring.boot.security.saml.web.core.OIDCLogoutSuccessHandler;
import com.vdenotaris.spring.boot.security.saml.web.core.SAMLLogoutFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.Filter;
import java.net.URI;

@Configuration
@EnableWebSecurity
@Order(10)
public class GlobalLogoutSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.antMatcher("/ensso/logout")
                .authorizeRequests().anyRequest().authenticated()
                .and().addFilterAfter(oidcLogoutFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(samlLogoutFilter(), BasicAuthenticationFilter.class);
        http.logout().disable();
    }

    @Bean("EnSsoSamlLogoutFilter")
    public Filter samlLogoutFilter() {
        //TODO: there is vulnerability here, it can't handle SAML logout response
        return new SAMLLogoutFilter(samlLogoutSuccessHandler(),
                new LogoutHandler[] { logoutHandler() },
                new LogoutHandler[] { logoutHandler() });
    }

    private Filter oidcLogoutFilter() {
        return new OIDCLogoutFilter(oidcLogoutSuccessHandler(),logoutHandler());
    }

    public SimpleUrlLogoutSuccessHandler samlLogoutSuccessHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        //TODO: read from cookie???
        successLogoutHandler.setDefaultTargetUrl("/ensso/idc/kc");
        return successLogoutHandler;
    }

    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler =
                new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OIDCLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OIDCLogoutSuccessHandler(this.clientRegistrationRepository);

        // Sets the `URI` that the End-User's User Agent will be redirected to
        // after the logout has been performed at the Provider
        //TODO: read from cookie???
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create("https://localhost:8080/ensso/idc/aad"));

        return oidcLogoutSuccessHandler;
    }
}
