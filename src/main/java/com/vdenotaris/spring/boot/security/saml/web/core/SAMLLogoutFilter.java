package com.vdenotaris.spring.boot.security.saml.web.core;

import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.Assert;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SAMLLogoutFilter extends LogoutFilter {
    protected static final Logger log = LoggerFactory.getLogger(SAMLLogoutFilter.class);

    protected SingleLogoutProfile profile;
    protected SAMLLogger samlLogger;
    protected SAMLContextProvider contextProvider;
    private String filterProcessesUrl;

    /**
     * Name of parameter of HttpRequest indicating whether this call should perform only local logout.
     * In case the value is true no global logout will be invoked.
     */
    protected static final String LOGOUT_PARAMETER = "local";

    /**
     * Handlers to be invoked during logout.
     */
    protected LogoutHandler[] globalHandlers;

    /**
     * URL this filter processes
     */
    public static final String FILTER_URL = "/ensso/logout";

    /**
     * Default constructor.
     *
     * @param successUrl     url to use after logout in case of local logout
     * @param localHandler   handlers to be invoked when local logout is selected
     * @param globalHandlers handlers to be invoked when global logout is selected
     */
    public SAMLLogoutFilter(String successUrl, LogoutHandler[] localHandler, LogoutHandler[] globalHandlers) {
        super(successUrl, localHandler);
        this.globalHandlers = globalHandlers;
        this.setFilterProcessesUrl(FILTER_URL);
    }

    /**
     * Default constructor.
     *
     * @param logoutSuccessHandler handler to invoke upon successful logout
     * @param localHandler         handlers to be invoked when local logout is selected
     * @param globalHandlers       handlers to be invoked when global logout is selected
     */
    public SAMLLogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler[] localHandler, LogoutHandler[] globalHandlers) {
        super(logoutSuccessHandler, localHandler);
        this.globalHandlers = globalHandlers;
        this.setFilterProcessesUrl(FILTER_URL);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        processLogout(fi.getRequest(), fi.getResponse(), chain);
    }

    /**
     * In case request parameter of name "local" is set to true or there is no authenticated user
     * only local logout will be performed and user will be redirected to the success page.
     * Otherwise global logout procedure is initialized.
     *
     * @param request  http request
     * @param response http response
     * @param chain    chain
     * @throws IOException      error
     * @throws ServletException error
     */
    public void processLogout(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (requiresLogout(request, response)) {

            try {

                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                EnSsoAuthenticationToken authn = (EnSsoAuthenticationToken) authentication;
                Authentication auth = (Authentication) authn.getOrigin();
                if (auth != null && isGlobalLogout(request, auth)) {

                    Assert.isInstanceOf(SAMLCredential.class, auth.getCredentials(), "Authentication object doesn't contain SAML credential, cannot perform global logout");

                    // Terminate the session first
                    for (LogoutHandler handler : globalHandlers) {
                        handler.logout(request, response, auth);
                    }

                    // Notify session participants using SAML Single Logout profile
                    SAMLCredential credential = (SAMLCredential) auth.getCredentials();
                    request.setAttribute(SAMLConstants.LOCAL_ENTITY_ID, credential.getLocalEntityID());
                    request.setAttribute(SAMLConstants.PEER_ENTITY_ID, credential.getRemoteEntityID());
                    SAMLMessageContext context = contextProvider.getLocalAndPeerEntity(request, response);
                    profile.sendLogoutRequest(context, credential);
                    samlLogger.log(SAMLConstants.LOGOUT_REQUEST, SAMLConstants.SUCCESS, context);

                } else {

                    super.doFilter(request, response, chain);

                }

            } catch (SAMLException e) {
                log.debug("Error initializing global logout", e);
                throw new ServletException("Error initializing global logout", e);
            } catch (MetadataProviderException e) {
                log.debug("Error processing metadata", e);
                throw new ServletException("Error processing metadata", e);
            } catch (MessageEncodingException e) {
                log.debug("Error encoding outgoing message", e);
                throw new ServletException("Error encoding outgoing message", e);
            }

        } else {

            chain.doFilter(request, response);
        }

    }

    /**
     * The filter will be used in case the URL of the request contains the DEFAULT_FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    @Override
    protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
        //TODO: check idp and url match
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        EnSsoAuthenticationToken authn = (EnSsoAuthenticationToken) authentication;
        String idp = authn.getIdp();
        return SAMLUtil.processFilter(getFilterProcessesUrl(), request) && "http://localhost:8081/auth/realms/demo".equals(idp);
    }

    /**
     * Performs global logout in case current user logged in using SAML and user hasn't selected local logout only
     *
     * @param request request
     * @param auth    currently logged in user
     * @return true if single logout with IDP is required
     */
    protected boolean isGlobalLogout(HttpServletRequest request, Authentication auth) {
        String localLogout = request.getParameter(LOGOUT_PARAMETER);
        return (localLogout == null || !"true".equals(localLogout.toLowerCase().trim())) && (auth.getCredentials() instanceof SAMLCredential);
    }

    /**
     * Logger for SAML events, cannot be null, must be set.
     *
     * @param samlLogger logger
     */
    @Autowired
    public void setSamlLogger(SAMLLogger samlLogger) {
        Assert.notNull(samlLogger, "SAML Logger can't be null");
        this.samlLogger = samlLogger;
    }

    /**
     * Profile for consumption of processed messages, cannot be null, must be set.
     *
     * @param profile profile
     */
    @Autowired
    public void setProfile(SingleLogoutProfile profile) {
        Assert.notNull(profile, "SingleLogoutProfile can't be null");
        this.profile = profile;
    }

    /**
     * Sets entity responsible for populating local entity context data. Cannot be null, must be set.
     *
     * @param contextProvider provider implementation
     */
    @Autowired
    public void setContextProvider(SAMLContextProvider contextProvider) {
        Assert.notNull(contextProvider, "Context provider can't be null");
        this.contextProvider = contextProvider;
    }

    /**
     * Verifies that required entities were autowired or set.
     */
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(profile, "Single logout profile must be set");
        Assert.notNull(contextProvider, "Context provider must be set");
        Assert.notNull(samlLogger, "SAML Logger must be set");
    }

    /**
     * Sets the URL used to determine if this Filter is invoked
     *
     * @param filterProcessesUrl the URL used to determine if this Filter is invoked
     */
    @Override
    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.filterProcessesUrl = filterProcessesUrl;
        super.setFilterProcessesUrl(filterProcessesUrl);
    }

    /**
     * Gets the URL used to determine if this Filter is invoked
     *
     * @return the URL used to determine if this Fitler is invoked
     */
    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }
}
