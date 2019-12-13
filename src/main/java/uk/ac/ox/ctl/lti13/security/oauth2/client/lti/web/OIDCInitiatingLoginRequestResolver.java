package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * This handles the initial part of the LTI 1.3 Resource Link Request and sends the browser back to the platform to
 * start the OAuth2 Implicit Flow.
 *
 * We will mount a copy of the Filter at /oauth2/login_initiation
 *
 * As this is currently targeting LTI 1.3 it will come back as a login to the OAuth2 filter.
 *
 * https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin
 * https://www.imsglobal.org/spec/security/v1p0/#step-1-third-party-initiated-login
 */
public class OIDCInitiatingLoginRequestResolver implements OAuth2AuthorizationRequestResolver {

    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final AntPathRequestMatcher authorizationRequestMatcher;
    // The IMS LTI 1.3 Validator doesn't include = (%3D URL encoded) in state tokens.
    // private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
    private final StringKeyGenerator stateGenerator = KeyGenerators.string();


    /**
     * Constructs a {@code DefaultOAuth2AuthorizationRequestResolver} using the provided parameters.
     *
     * @param clientRegistrationRepository the repository of client registrations
     * @param authorizationRequestBaseUri the base {@code URI} used for resolving authorization requests
     */
    public OIDCInitiatingLoginRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
                                                     String authorizationRequestBaseUri) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizationRequestMatcher = new AntPathRequestMatcher(
                authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String registrationId = this.resolveRegistrationId(request);
        return resolve(request, registrationId, "login");
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId) {
        if (registrationId == null) {
            return null;
        }
        return resolve(request, registrationId, "login");
    }

    private OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId, String redirectUriAction) {
        if (registrationId == null) {
            return null;
        }

        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        if (clientRegistration == null) {
            throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
        }

        OAuth2AuthorizationRequest.Builder builder;
        // For now we only support implicit grants.
        if (AuthorizationGrantType.IMPLICIT.equals(clientRegistration.getAuthorizationGrantType())) {
            builder = OAuth2AuthorizationRequest.implicit();
        } else {
            throw new IllegalArgumentException("Invalid Authorization Grant Type ("  +
                    clientRegistration.getAuthorizationGrantType().getValue() +
                    ") for Client Registration with Id: " + clientRegistration.getRegistrationId());
        }

        String iss = request.getParameter("iss");
        if (iss == null) {
            throw new IllegalArgumentException("Required parameter iss was not supplied.");
        }

        String loginHint = request.getParameter("login_hint");
        if (loginHint == null) {
            throw new IllegalArgumentException("Required parameter login_hint was not supplied.");
        }

        String targetLinkUri = request.getParameter("target_link_uri");
        if (targetLinkUri == null) {
            throw new IllegalArgumentException("Required parameter target_link_uri was not supplied");
        }

        String redirectUriStr = this.expandRedirectUri(request, clientRegistration, redirectUriAction);


        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());
        // IMS SEC 1.0
        // OIDC allows for "id_token token" or "id_token". In LTI the id_token is also the access token.
        // This overrides the initial value set for this.
        additionalParameters.put(OAuth2ParameterNames.RESPONSE_TYPE, "id_token");
        additionalParameters.put("login_hint", loginHint);
        additionalParameters.put("response_mode", "form_post");
        additionalParameters.put("nonce", UUID.randomUUID().toString());
        additionalParameters.put("prompt", "none");

        // IMS LTI 1.3
        String ltiMessageHint = request.getParameter("lti_message_hint");
        if (ltiMessageHint != null) {
            additionalParameters.put("lti_message_hint", ltiMessageHint);
        }

        OAuth2AuthorizationRequest authorizationRequest = builder
                .clientId(clientRegistration.getClientId())
                .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
                .redirectUri(redirectUriStr)
                .scopes(clientRegistration.getScopes())
                .state(this.stateGenerator.generateKey())
                .additionalParameters(additionalParameters)
                .build();

        return authorizationRequest;
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        if (this.authorizationRequestMatcher.matches(request)) {
            return this.authorizationRequestMatcher
                    .extractUriTemplateVariables(request).get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }

    private String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration, String action) {
        // Supported URI variables -> baseUrl, action, registrationId
        // Used in -> CommonOAuth2Provider.DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}"
        Map<String, String> uriVariables = new HashMap<>();
        uriVariables.put("registrationId", clientRegistration.getRegistrationId());
        String baseUrl = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replaceQuery(null)
                .replacePath(request.getContextPath())
                .build()
                .toUriString();
        uriVariables.put("baseUrl", baseUrl);
        if (action != null) {
            uriVariables.put("action", action);
        }
        return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate())
                .buildAndExpand(uriVariables)
                .toUriString();
    }
}
