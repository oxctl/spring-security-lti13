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
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.authentication.OidcLaunchFlowAuthenticationProvider;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.authentication.TargetLinkUriAuthenticationSuccessHandler;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web.OAuth2AuthorizationRequestRedirectFilter;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web.OAuth2LoginAuthenticationFilter;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web.OIDCInitiatingLoginRequestResolver;

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

    private String ltiPath = "/lti";
    private String loginPath = "/login";
    private String loginInitiationPath = "/login_initiation";
    private ApplicationEventPublisher applicationEventPublisher;
    private GrantedAuthoritiesMapper grantedAuthoritiesMapper;

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

    @SuppressWarnings("unchecked")
    @Override
    public void init(HttpSecurity http) {
        // Allow LTI launches to bypass CSRF protection
        CsrfConfigurer configurer = http.getConfigurer(CsrfConfigurer.class);
        if (configurer != null) {
            configurer.ignoringAntMatchers(ltiPath + "/**");
        }
        // In the future we should use CSP to limit the domains that can embed this tool
        HeadersConfigurer headersConfigurer = http.getConfigurer(HeadersConfigurer.class);
        if (headersConfigurer != null) {
            headersConfigurer.frameOptions().disable();
        }
    }

    @Override
    public void configure(HttpSecurity http) {
        ClientRegistrationRepository clientRegistrationRepository = Lti13ConfigurerUtils.getClientRegistrationRepository(http);

        OidcLaunchFlowAuthenticationProvider oidcLaunchFlowAuthenticationProvider = configureAuthenticationProvider(http);
        // This handles step 1 of the IMS SEC
        // https://www.imsglobal.org/spec/security/v1p0/#step-1-third-party-initiated-login
        http.addFilterAfter(configureInitiationFilter(clientRegistrationRepository), LogoutFilter.class);
        // This handles step 3 of the IMS SEC
        // https://www.imsglobal.org/spec/security/v1p0/#step-3-authentication-response
        http.addFilterAfter(configureLoginFilter(clientRegistrationRepository, oidcLaunchFlowAuthenticationProvider), AbstractPreAuthenticatedProcessingFilter.class);
    }

    protected OidcLaunchFlowAuthenticationProvider configureAuthenticationProvider(HttpSecurity http) {
        OidcLaunchFlowAuthenticationProvider oidcLaunchFlowAuthenticationProvider = new OidcLaunchFlowAuthenticationProvider();

        http.authenticationProvider(oidcLaunchFlowAuthenticationProvider);
        if (grantedAuthoritiesMapper != null) {
            oidcLaunchFlowAuthenticationProvider.setAuthoritiesMapper(grantedAuthoritiesMapper);
        }
        return oidcLaunchFlowAuthenticationProvider;
    }

    protected OAuth2AuthorizationRequestRedirectFilter configureInitiationFilter(ClientRegistrationRepository clientRegistrationRepository) {
        OIDCInitiatingLoginRequestResolver resolver = new OIDCInitiatingLoginRequestResolver(clientRegistrationRepository, ltiPath+ loginInitiationPath);
        return new OAuth2AuthorizationRequestRedirectFilter(resolver);
    }

    protected OAuth2LoginAuthenticationFilter configureLoginFilter(ClientRegistrationRepository clientRegistrationRepository, OidcLaunchFlowAuthenticationProvider oidcLaunchFlowAuthenticationProvider) {
        OAuth2LoginAuthenticationFilter loginFilter = new OAuth2LoginAuthenticationFilter(clientRegistrationRepository, ltiPath+ loginPath);
        // This is to find the URL that we should redirect the user to.
        TargetLinkUriAuthenticationSuccessHandler successHandler = new TargetLinkUriAuthenticationSuccessHandler();
        loginFilter.setAuthenticationSuccessHandler(successHandler);
        ProviderManager authenticationManager = new ProviderManager(Collections.singletonList(oidcLaunchFlowAuthenticationProvider));
        if (applicationEventPublisher != null) {
            authenticationManager.setAuthenticationEventPublisher(new DefaultAuthenticationEventPublisher(applicationEventPublisher));
        }
        loginFilter.setAuthenticationManager(authenticationManager);
        return loginFilter;
    }

}