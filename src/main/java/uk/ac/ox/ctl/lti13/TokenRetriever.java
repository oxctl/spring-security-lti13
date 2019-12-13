package uk.ac.ox.ctl.lti13;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.security.KeyPair;
import java.time.Instant;
import java.util.*;

/**
 * This gets a token to use for LTI Services.
 * It uses the public/private key associated with a client registration to sign a JWT which is then used to obtain
 * an access token.
 *
 * @see <a href="https://www.imsglobal.org/spec/lti/v1p3/#token-endpoint-claim-and-services">https://www.imsglobal.org/spec/lti/v1p3/#token-endpoint-claim-and-services</a>
 * @see <a href="https://www.imsglobal.org/spec/security/v1p0/#using-json-web-tokens-with-oauth-2-0-client-credentials-grant">https://www.imsglobal.org/spec/security/v1p0/#using-json-web-tokens-with-oauth-2-0-client-credentials-grant</a>
 */
@Component
public class TokenRetriever {

    private final Logger log = LoggerFactory.getLogger(TokenRetriever.class);

    // Lifetime of our JWT in seconds
    private int jwtLifetime = 60;

    private final KeyPairService keyPairService;
    private final RestTemplate restTemplate;

    public TokenRetriever(KeyPairService keyPairService) {
        this.keyPairService = keyPairService;
        restTemplate = new RestTemplate(Arrays.asList(
                new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
    }

    public void setJwtLifetime(int jwtLifetime) {
        this.jwtLifetime = jwtLifetime;
    }

    public OAuth2AccessTokenResponse getToken(ClientRegistration clientRegistration, String... scopes) throws JOSEException {
        if (scopes.length == 0) {
            throw new IllegalArgumentException("You must supply some scopes to request.");
        }
        Objects.requireNonNull(clientRegistration, "You must supply a clientRegistration.");

        SignedJWT signedJWT = createJWT(clientRegistration);
        MultiValueMap<String, String> formData = buildFormData(signedJWT, scopes);
        // We are using RestTemplate here as that's what the existing OAuth2 code in Spring uses at the moment.
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));
        RequestEntity<MultiValueMap<String, String>> requestEntity = new RequestEntity<>(
                formData, headers, HttpMethod.POST, URI.create(clientRegistration.getProviderDetails().getTokenUri())
        );
        ResponseEntity<OAuth2AccessTokenResponse> exchange = restTemplate.exchange(requestEntity, OAuth2AccessTokenResponse.class);
        return exchange.getBody();
    }

    private SignedJWT createJWT(ClientRegistration clientRegistration) throws JOSEException {
        KeyPair keyPair = keyPairService.getKeyPair(clientRegistration.getRegistrationId());
        if (keyPair == null) {
            throw new NullPointerException(
                    "Failed to get keypair for client registration: "+ clientRegistration.getRegistrationId()
            );
        }

        RSASSASigner signer = new RSASSASigner(keyPair.getPrivate());

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                // Both must be set to client ID according to spec.
                .issuer(clientRegistration.getClientId())
                .subject(clientRegistration.getClientId())
                .audience(clientRegistration.getProviderDetails().getTokenUri())
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                // 60 Seconds
                .expirationTime(Date.from(Instant.now().plusSeconds(jwtLifetime)))
                .build();

        // We don't have to include a key ID.
        JWSHeader jwt = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
        SignedJWT signedJWT = new SignedJWT(jwt, claimsSet);
        signedJWT.sign(signer);

        if (log.isDebugEnabled()) {
            log.debug("Created signed token: {}", signedJWT.serialize());
        }

        return signedJWT;
    }

    private MultiValueMap<String, String> buildFormData(SignedJWT signedJWT, String[] scopes) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        formData.add("scope", String.join(" ", scopes));
        formData.add("client_assertion", signedJWT.serialize());
        return formData;
    }

}
