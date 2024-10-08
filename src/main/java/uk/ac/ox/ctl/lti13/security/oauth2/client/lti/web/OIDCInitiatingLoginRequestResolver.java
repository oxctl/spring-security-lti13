package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * This handles the initial part of the LTI 1.3 Resource Link Request and sends the browser back to the platform to
 * start the OAuth2 Implicit Flow.
 *
 * We will mount a copy of the Filter at /lti/login_initiation
 *
 * As this is currently targeting LTI 1.3 it will come back as a login to the OAuth2 filter.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin">OpenID ThirdPartyInitiatedLogin</a>
 * @see <a href="https://www.imsglobal.org/spec/security/v1p0/#step-1-third-party-initiated-login">IMS ThirdPartyInitiatedLogin</a>
 */
public class OIDCInitiatingLoginRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OIDCInitiationRegistrationResolver registrationResolver;
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
        this.registrationResolver = new PathOIDCInitiationRegistrationResolver(authorizationRequestBaseUri);
    }

    /**
     * Constructs a {@code DefaultOAuth2AuthorizationRequestResolver} using the provided parameters.
     *
     * @param clientRegistrationRepository the repository of client registrations
     * @param registrationResolver a resolver that looks up the registration ID from the request
     */
    public OIDCInitiatingLoginRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
                                              OIDCInitiationRegistrationResolver registrationResolver) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(registrationResolver, "registrationResolver cannot be null");
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.registrationResolver = registrationResolver;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String registrationId = this.registrationResolver.resolve(request);
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
            // We use a custom exception here so callers can specifically handle this case.
            throw new InvalidClientRegistrationIdException("No Client Registration found with ID: " + registrationId);
        }

        OAuth2AuthorizationRequest.Builder builder;
        if (LTIAuthorizationGrantType.IMPLICIT.equals(clientRegistration.getAuthorizationGrantType())) {
            // We are performing an implicit grand but this isn't supported by Spring Security any more
            // so we pretend it's actually auth code.
            builder = OAuth2AuthorizationRequest.authorizationCode();
        } else {
            // This is a configuration problem.
            throw new IllegalArgumentException("Invalid Authorization Grant Type ("  +
                    clientRegistration.getAuthorizationGrantType().getValue() +
                    ") for Client Registration with Id: " + clientRegistration.getRegistrationId());
        }

        String iss = request.getParameter("iss");
        if (iss == null) {
            throw new InvalidInitiationRequestException("Required parameter iss was not supplied.");
        }

        String loginHint = request.getParameter("login_hint");
        if (loginHint == null) {
            throw new InvalidInitiationRequestException("Required parameter login_hint was not supplied.");
        }

        String targetLinkUri = request.getParameter("target_link_uri");
        if (targetLinkUri == null) {
            throw new InvalidInitiationRequestException("Required parameter target_link_uri was not supplied");
        }

        // The client_id parameter is optional, but if it's supplied check it matches.
        String clientId = request.getParameter("client_id");
        if (clientId != null) {
            if (!clientId.equals(clientRegistration.getClientId())) {
                throw new IllegalArgumentException("Parameter client_id ("+clientId+") doesn't match the configured registration ("+ clientRegistration.getClientId()+").");
            }
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
        // TODO We should really have a custom object for LTI launches
        additionalParameters.put("nonce", UUID.randomUUID().toString());
        additionalParameters.put("prompt", "none");

        // IMS LTI 1.3
        String ltiMessageHint = request.getParameter("lti_message_hint");
        if (ltiMessageHint != null) {
            additionalParameters.put("lti_message_hint", ltiMessageHint);
        }
        
        // These are additional parameters that we want to keep but they aren't part of the message
        Map<String, Object> attributes = new HashMap<>();
        // This is so that we can check the first and last requests of the login are from
        // the same IP address.
        attributes.put(StateAuthorizationRequestRepository.REMOTE_IP, request.getRemoteAddr());

        OAuth2AuthorizationRequest authorizationRequest = builder
                .clientId(clientRegistration.getClientId())
                .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
                .redirectUri(redirectUriStr)
                .scopes(clientRegistration.getScopes())
                .state(this.stateGenerator.generateKey())
                .additionalParameters(additionalParameters)
                .attributes(attributes)
                .build();

        return authorizationRequest;
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
        return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUri())
                .buildAndExpand(uriVariables)
                .toUriString();
    }
}
