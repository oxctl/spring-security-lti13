package uk.ac.ox.ctl.lti13;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
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
public class Lti13Configurer  extends AbstractHttpConfigurer<Lti13Configurer, HttpSecurity> {

    private final String loginPath = "/login";
    private final String loginInitiationPath = "/login_initiation";
    private String ltiPath = "/lti";
    private ApplicationEventPublisher applicationEventPublisher;

    public Lti13Configurer ltiPath(String ltiPath) {
        this.ltiPath = ltiPath;
        return this;
    }

    public Lti13Configurer applicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
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

        OidcLaunchFlowAuthenticationProvider oidcLaunchFlowAuthenticationProvider = new OidcLaunchFlowAuthenticationProvider();
        http.authenticationProvider(oidcLaunchFlowAuthenticationProvider);
//        oidcLaunchFlowAuthenticationProvider.setAuthoritiesMapper(new LtiAuthoritiesMapper());
        // This handles step 1 of the IMS SEC

        http.addFilterAfter(configureInitiationFilter(clientRegistrationRepository), LogoutFilter.class);
        http.addFilterAfter(configureLoginFilter(clientRegistrationRepository, oidcLaunchFlowAuthenticationProvider), AbstractPreAuthenticatedProcessingFilter.class);
    }

    private OAuth2AuthorizationRequestRedirectFilter configureInitiationFilter(ClientRegistrationRepository clientRegistrationRepository) {
        OIDCInitiatingLoginRequestResolver resolver = new OIDCInitiatingLoginRequestResolver(clientRegistrationRepository, ltiPath+ loginInitiationPath);
        return new OAuth2AuthorizationRequestRedirectFilter(resolver);
    }

    private OAuth2LoginAuthenticationFilter configureLoginFilter(ClientRegistrationRepository clientRegistrationRepository, OidcLaunchFlowAuthenticationProvider oidcLaunchFlowAuthenticationProvider) {
        // This handles the actual login
        OAuth2LoginAuthenticationFilter loginFilter = new OAuth2LoginAuthenticationFilter(clientRegistrationRepository, ltiPath+ loginPath);
        // This is to redirect things back the frontend
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