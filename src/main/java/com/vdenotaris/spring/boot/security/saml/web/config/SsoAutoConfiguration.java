package com.vdenotaris.spring.boot.security.saml.web.config;

import com.vdenotaris.spring.boot.security.saml.web.core.DefaultEnSsoLandingHandler;
import com.vdenotaris.spring.boot.security.saml.web.core.EnSsoLandingHandler;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SsoAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public EnSsoLandingHandler enSsoLandingHandler(){
        return new DefaultEnSsoLandingHandler();
    }
}
