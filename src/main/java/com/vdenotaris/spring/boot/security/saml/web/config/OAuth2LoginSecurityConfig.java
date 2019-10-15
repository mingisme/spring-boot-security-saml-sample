package com.vdenotaris.spring.boot.security.saml.web.config;


import com.vdenotaris.spring.boot.security.saml.web.core.DefaultEnSsoLandingFilter;
import com.vdenotaris.spring.boot.security.saml.web.core.OAuth2AuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import java.net.URI;

@Configuration
@EnableWebSecurity
@Order(50)
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2AuthenticationSuccessHandler successHandler;

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //TODO: configuration of urls that read value from SecurityContextHolder.getContext().getAuthentication().
        http.requestMatcher(new OrRequestMatcher(new AntPathRequestMatcher("/login/oauth2/**"), new AntPathRequestMatcher("/oauth2/**")));
        http.addFilterAfter(new DefaultEnSsoLandingFilter(), ExceptionTranslationFilter.class);
        http.authorizeRequests().anyRequest().authenticated();
        http.oauth2Login().successHandler(successHandler);
        http.oauth2Client();
        //TODO: logout should be handled later
        http.logout(logout ->logout.logoutSuccessHandler(oidcLogoutSuccessHandler()));
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);

        // Sets the `URI` that the End-User's User Agent will be redirected to
        // after the logout has been performed at the Provider
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create("https://localhost:8080"));

        return oidcLogoutSuccessHandler;
    }
}
