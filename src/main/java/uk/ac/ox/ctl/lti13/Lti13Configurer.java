package uk.ac.ox.ctl.lti13;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import uk.ac.ox.ctl.lti13.security.oauth2.OAuthAuthenticationFailureHandler;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.authentication.OidcLaunchFlowAuthenticationProvider;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.authentication.TargetLinkUriAuthenticationSuccessHandler;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web.OAuth2AuthorizationRequestRedirectFilter;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web.OAuth2LoginAuthenticationFilter;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web.OIDCInitiatingLoginRequestResolver;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web.OptimisticAuthorizationRequestRepository;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web.StateAuthorizationRequestRepository;

import java.time.Duration;
import java.util.Collections;


/**
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository}</li>
 * </ul>
 */
public class Lti13Configurer extends AbstractHttpConfigurer<Lti13Configurer, HttpSecurity> {

    protected String ltiPath = "/lti";
    protected String loginPath = "/login";
    protected String loginInitiationPath = "/login_initiation";
    protected ApplicationEventPublisher applicationEventPublisher;
    protected GrantedAuthoritiesMapper grantedAuthoritiesMapper;
    protected boolean limitIpAddresses;

    public Lti13Configurer ltiPath(String ltiPath) {
        this.ltiPath = ltiPath;
        return this;
    }

    public Lti13Configurer loginPath(String loginPath) {
        this.loginPath = loginPath;
        return this;
    }

    public Lti13Configurer loginInitiationPath(String loginInitiationPath) {
        this.loginInitiationPath = loginInitiationPath;
        return this;
    }

    public Lti13Configurer applicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
        return this;
    }

    public Lti13Configurer grantedAuthoritiesMapper(GrantedAuthoritiesMapper grantedAuthoritiesMapper) {
        this.grantedAuthoritiesMapper = grantedAuthoritiesMapper;
        return this;
    }

    /**
     * Using this may cause problems for users who are behind a proxy or NAT setup that uses different IP addresses
     * for different requests, even if they are close together in time.
     * 
     * @param limitIpAddresses if true then ensure that all the OAuth requests for a LTI launch come from the same IP
     */
    public Lti13Configurer limitIpAddresses(boolean limitIpAddresses) {
        this.limitIpAddresses = limitIpAddresses;
        return this;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void init(HttpSecurity http) {
        // Allow LTI launches to bypass CSRF protection
        CsrfConfigurer<HttpSecurity> configurer = http.getConfigurer(CsrfConfigurer.class);
        if (configurer != null) {
            configurer.ignoringAntMatchers(ltiPath + "/**");
        }
        // In the future we should use CSP to limit the domains that can embed this tool
        HeadersConfigurer<HttpSecurity> headersConfigurer = http.getConfigurer(HeadersConfigurer.class);
        if (headersConfigurer != null) {
            headersConfigurer.frameOptions().disable();
        }
    }

    @Override
    public void configure(HttpSecurity http) {
        ClientRegistrationRepository clientRegistrationRepository = Lti13ConfigurerUtils.getClientRegistrationRepository(http);

        OidcLaunchFlowAuthenticationProvider oidcLaunchFlowAuthenticationProvider = configureAuthenticationProvider(http);
        OptimisticAuthorizationRequestRepository authorizationRequestRepository = configureRequestRepository();
        // This handles step 1 of the IMS SEC
        // https://www.imsglobal.org/spec/security/v1p0/#step-1-third-party-initiated-login
        http.addFilterAfter(configureInitiationFilter(clientRegistrationRepository, authorizationRequestRepository), LogoutFilter.class);
        // This handles step 3 of the IMS SEC
        // https://www.imsglobal.org/spec/security/v1p0/#step-3-authentication-response
        http.addFilterAfter(configureLoginFilter(clientRegistrationRepository, oidcLaunchFlowAuthenticationProvider, authorizationRequestRepository), AbstractPreAuthenticatedProcessingFilter.class);
    }

    protected OptimisticAuthorizationRequestRepository configureRequestRepository() {
        HttpSessionOAuth2AuthorizationRequestRepository sessionRepository = new HttpSessionOAuth2AuthorizationRequestRepository();
        StateAuthorizationRequestRepository stateRepository = new StateAuthorizationRequestRepository(Duration.ofMinutes(1));
        stateRepository.setLimitIpAddress(limitIpAddresses);
        return new OptimisticAuthorizationRequestRepository( sessionRepository, stateRepository );
    }

    protected OidcLaunchFlowAuthenticationProvider configureAuthenticationProvider(HttpSecurity http) {
        OidcLaunchFlowAuthenticationProvider oidcLaunchFlowAuthenticationProvider = new OidcLaunchFlowAuthenticationProvider();

        http.authenticationProvider(oidcLaunchFlowAuthenticationProvider);
        if (grantedAuthoritiesMapper != null) {
            oidcLaunchFlowAuthenticationProvider.setAuthoritiesMapper(grantedAuthoritiesMapper);
        }
        return oidcLaunchFlowAuthenticationProvider;
    }

    protected OAuth2AuthorizationRequestRedirectFilter configureInitiationFilter(ClientRegistrationRepository clientRegistrationRepository,  OptimisticAuthorizationRequestRepository authorizationRequestRepository) {
        OIDCInitiatingLoginRequestResolver resolver = new OIDCInitiatingLoginRequestResolver(clientRegistrationRepository, ltiPath+ loginInitiationPath);
        OAuth2AuthorizationRequestRedirectFilter filter = new OAuth2AuthorizationRequestRedirectFilter(resolver);
        filter.setAuthorizationRequestRepository(authorizationRequestRepository);
        return filter;
    }

    protected OAuth2LoginAuthenticationFilter configureLoginFilter(ClientRegistrationRepository clientRegistrationRepository, OidcLaunchFlowAuthenticationProvider oidcLaunchFlowAuthenticationProvider, OptimisticAuthorizationRequestRepository authorizationRequestRepository) {
        // This filter handles the actual authentication and behaviour of errors
        OAuth2LoginAuthenticationFilter loginFilter = new OAuth2LoginAuthenticationFilter(clientRegistrationRepository, ltiPath+ loginPath);
        // This is to find the URL that we should redirect the user to.
        TargetLinkUriAuthenticationSuccessHandler successHandler = new TargetLinkUriAuthenticationSuccessHandler(authorizationRequestRepository);
        loginFilter.setAuthenticationSuccessHandler(successHandler);
        // This is just so that you can get better error messages when something goes wrong.
        OAuthAuthenticationFailureHandler failureHandler = new OAuthAuthenticationFailureHandler();
        loginFilter.setAuthenticationFailureHandler(failureHandler);
        loginFilter.setAuthorizationRequestRepository(authorizationRequestRepository);
        ProviderManager authenticationManager = new ProviderManager(Collections.singletonList(oidcLaunchFlowAuthenticationProvider));
        if (applicationEventPublisher != null) {
            authenticationManager.setAuthenticationEventPublisher(new DefaultAuthenticationEventPublisher(applicationEventPublisher));
        }
        loginFilter.setAuthenticationManager(authenticationManager);
        return loginFilter;
    }

}