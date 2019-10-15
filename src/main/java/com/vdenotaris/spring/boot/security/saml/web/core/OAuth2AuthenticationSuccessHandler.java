package com.vdenotaris.spring.boot.security.saml.web.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;


@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private EnSsoLandingHandler landingHandler;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if(authentication instanceof OAuth2AuthenticationToken){
            OAuth2AuthenticationToken oauth2AuthenticationToken = (OAuth2AuthenticationToken)authentication;
            OAuth2User oAuth2User = oauth2AuthenticationToken.getPrincipal();
            //TODO: get nameAttributeKey from configuration
            String nameAttributeKey="preferred_username";
            String firstNameAttributeKey="given_name";
            String lastNameAttributeKey="family_name";
            String emailAttribueKey="preferred_username";
            String phoneAttribueKey="phone";
            String nickNameAttributeKey="name";
            MultiValueMap<String, Object> attributes = new LinkedMultiValueMap<>();
            for(Map.Entry<String,Object> att : oAuth2User.getAttributes().entrySet()){
                attributes.add(att.getKey(),att.getValue());
            }

            EnSsoUser user = new EnSsoUser(nameAttributeKey, firstNameAttributeKey, lastNameAttributeKey, emailAttribueKey, phoneAttribueKey, nickNameAttributeKey, attributes,oAuth2User.getAuthorities(),oAuth2User);
            EnSsoAuthenticationToken token = new EnSsoAuthenticationToken(user,oauth2AuthenticationToken.getCredentials(),oauth2AuthenticationToken.getAuthorities(), ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId(), oauth2AuthenticationToken);
            SecurityContextHolder.getContext().setAuthentication(token);

            landingHandler.handle(request,response,token);

            response.sendRedirect("/ensso/landing");
        }else{
            throw new RuntimeException("Spring Security incompatible upgrade");
        }
    }
}
