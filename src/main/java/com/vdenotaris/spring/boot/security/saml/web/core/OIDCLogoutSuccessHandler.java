package com.vdenotaris.spring.boot.security.saml.web.core;


import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;

public class OIDCLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
    private final ClientRegistrationRepository clientRegistrationRepository;

    private URI postLogoutRedirectUri;

    public OIDCLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request,
                                        HttpServletResponse response, Authentication auth) {
        String targetUrl = null;
        URI endSessionEndpoint;

        EnSsoAuthenticationToken authn = (EnSsoAuthenticationToken) auth;
        Authentication authentication= authn.getOrigin();
        if (authentication instanceof OAuth2AuthenticationToken && authentication.getPrincipal() instanceof OidcUser) {
            endSessionEndpoint = this.endSessionEndpoint((OAuth2AuthenticationToken) authentication);
            if (endSessionEndpoint != null) {
                targetUrl = endpointUri(endSessionEndpoint, authentication);
            }
        }
        if (targetUrl == null) {
            targetUrl = super.determineTargetUrl(request, response);
        }

        return targetUrl;
    }

    private URI endSessionEndpoint(OAuth2AuthenticationToken token) {
        String registrationId = token.getAuthorizedClientRegistrationId();
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

        URI result = null;
        if (clientRegistration != null) {
            Object endSessionEndpoint = clientRegistration.getProviderDetails().getConfigurationMetadata().get("end_session_endpoint");
            if (endSessionEndpoint != null) {
                result = URI.create(endSessionEndpoint.toString());
            }
        }

        return result;
    }

    private String endpointUri(URI endSessionEndpoint, Authentication authentication) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endSessionEndpoint);
        builder.queryParam("id_token_hint", idToken(authentication));
        if (this.postLogoutRedirectUri != null) {
            builder.queryParam("post_logout_redirect_uri", this.postLogoutRedirectUri);
        }
        return builder.encode(StandardCharsets.UTF_8).build().toUriString();
    }

    private String idToken(Authentication authentication) {
        return ((OidcUser) authentication.getPrincipal()).getIdToken().getTokenValue();
    }

    /**
     * Set the post logout redirect uri to use
     *
     * @param postLogoutRedirectUri - A valid URL to which the OP should redirect after logging out the user
     */
    public void setPostLogoutRedirectUri(URI postLogoutRedirectUri) {
        Assert.notNull(postLogoutRedirectUri, "postLogoutRedirectUri cannot be null");
        this.postLogoutRedirectUri = postLogoutRedirectUri;
    }
}
