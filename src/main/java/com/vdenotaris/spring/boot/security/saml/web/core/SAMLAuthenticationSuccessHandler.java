package com.vdenotaris.spring.boot.security.saml.web.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Component
public class SAMLAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private EnSsoLandingHandler landingHandler;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if(authentication instanceof ExpiringUsernameAuthenticationToken){
            ExpiringUsernameAuthenticationToken samlAuthenticationToken = (ExpiringUsernameAuthenticationToken)authentication;
            SAMLUser principal = (SAMLUser)samlAuthenticationToken.getPrincipal();
            SAMLCredential credential = (SAMLCredential)samlAuthenticationToken.getCredentials();

            //TODO: get nameAttributeKey from configuration
            String nameAttributeKey="email";
            String firstNameAttributeKey="givenName";
            String lastNameAttributeKey="surname";
            String emailAttribueKey="email";
            String phoneAttribueKey="phone";
            String nickNameAttributeKey="name";

            EnSsoUser user = new EnSsoUser(nameAttributeKey, firstNameAttributeKey, lastNameAttributeKey, emailAttribueKey, phoneAttribueKey, nickNameAttributeKey, principal.getAttributes(),principal.getAuthorities(),principal);
            EnSsoAuthenticationToken token = new EnSsoAuthenticationToken(user,credential,samlAuthenticationToken.getAuthorities(), credential.getRemoteEntityID(), samlAuthenticationToken);
            SecurityContextHolder.getContext().setAuthentication(token);

            landingHandler.handle(request,response,token);

            response.sendRedirect("/ensso/landing");
        }else{
            throw new RuntimeException("Spring Security SAML extension incompatible upgrade");
        }
    }
}
