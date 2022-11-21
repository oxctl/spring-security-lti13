package uk.ac.ox.ctl.lti13.stateful;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestOperations;
import org.springframework.web.context.WebApplicationContext;
import uk.ac.ox.ctl.lti13.Lti13Configurer;
import uk.ac.ox.ctl.lti13.config.Lti13Configuration;
import uk.ac.ox.ctl.lti13.lti.Claims;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.authentication.OidcLaunchFlowAuthenticationProvider;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web.OAuth2LoginAuthenticationFilter;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web.OptimisticAuthorizationRequestRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static uk.ac.ox.ctl.lti13.stateful.Lti13Step3Test.CustomLti13Configuration;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@SpringJUnitWebConfig(classes = {CustomLti13Configuration.class})
public class Lti13Step3Test {

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext wac;

    @Autowired
    private RestOperations restOperations;

    @Autowired
    private KeyPair keyPair;

    @Autowired
    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;


    @Configuration
    @EnableWebSecurity
    public static class CustomLti13Configuration extends Lti13Configuration {

        @Autowired
        private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

        @Autowired
        private RestOperations restOperations;

        @Bean
        AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
            return mock(AuthorizationRequestRepository.class);
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests().anyRequest().authenticated();
            Lti13Configurer lti13Configurer = new Lti13Configurer() {

                @Override
                protected OidcLaunchFlowAuthenticationProvider configureAuthenticationProvider(HttpSecurity http) {
                    // This is so that we can mock out the HTTP response for the JWKs URL.
                    OidcLaunchFlowAuthenticationProvider oidcLaunchFlowAuthenticationProvider = super.configureAuthenticationProvider(http);
                    oidcLaunchFlowAuthenticationProvider.setRestOperations(restOperations);
                    return oidcLaunchFlowAuthenticationProvider;
                }

                @Override
                protected OAuth2LoginAuthenticationFilter configureLoginFilter(ClientRegistrationRepository clientRegistrationRepository, OidcLaunchFlowAuthenticationProvider oidcLaunchFlowAuthenticationProvider, OptimisticAuthorizationRequestRepository authorizationRequestRepository) {
                    // This is so that we can put a fake original request into the repository so that the state between
                    // the fake request and out test request will match.
                    OAuth2LoginAuthenticationFilter oAuth2LoginAuthenticationFilter = super.configureLoginFilter(clientRegistrationRepository, oidcLaunchFlowAuthenticationProvider, authorizationRequestRepository);
                    // Set a custom request repository
                    oAuth2LoginAuthenticationFilter.setAuthorizationRequestRepository(
                            CustomLti13Configuration.this.authorizationRequestRepository
                    );
                    return oAuth2LoginAuthenticationFilter;
                }
            };
            http.apply(lti13Configurer);
        }
    }

    @Before
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(wac)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    public void testSecured() throws Exception {
        this.mockMvc.perform(get("/"))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testStep3SignedToken() throws Exception {
        JWTClaimsSet claims = createClaims().build();

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = createAuthRequest().build();

        when(authorizationRequestRepository.removeAuthorizationRequest(any(HttpServletRequest.class), any(HttpServletResponse.class)))
                .thenReturn(oAuth2AuthorizationRequest);

        when(restOperations.exchange(any(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(jwkSet().toString(), HttpStatus.OK));
        mockMvc.perform(get("/lti/login").param("id_token", createJWT(claims)).param("state", "state"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    public void testStep3WrongVersion() throws Exception {
        // Remove the LTI Version.
        JWTClaimsSet claims = createClaims().claim(Claims.LTI_VERSION, null).build();

        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = createAuthRequest().build();

        when(authorizationRequestRepository.removeAuthorizationRequest(any(HttpServletRequest.class), any(HttpServletResponse.class)))
                .thenReturn(oAuth2AuthorizationRequest);

        when(restOperations.exchange(any(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(jwkSet().toString(), HttpStatus.OK));
        mockMvc.perform(get("/lti/login").param("id_token", createJWT(claims)).param("state", "state"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    public void testStep3Empty() throws Exception {
        this.mockMvc.perform(get("/lti/login"))
                .andExpect(status().is4xxClientError());
    }

    private OAuth2AuthorizationRequest.Builder createAuthRequest() {
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, "test");
        return OAuth2AuthorizationRequest.implicit()
                .authorizationUri("https://platform.test/auth/new")
                .redirectUri("https://tool.test/lti/login")
                .scope("openid")
                .state("state")
                .additionalParameters(additionalParameters)
                .clientId("test-id");
    }

    private String createJWT(JWTClaimsSet claims) throws JOSEException {
        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

        SignedJWT jwt = new SignedJWT(header, claims);
        JWSSigner signer = new RSASSASigner(keyPair.getPrivate());
        jwt.sign(signer);
        return jwt.serialize();
    }

    private JWTClaimsSet.Builder createClaims() {
        return new JWTClaimsSet.Builder()
                    .issuer("https://platform.test")
                    .subject("subject")
                    .claim("scope", "openid")
                    .audience("test-id")
                    .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                    .claim("nonce", "test-nonce")
                    .claim(Claims.LTI_VERSION, "1.3.0")
                    .claim(Claims.MESSAGE_TYPE, "unchecked")
                    .claim(Claims.ROLES, "")
                    .claim(Claims.LTI_DEPLOYMENT_ID, "1");
    }

    private JWKSet jwkSet() {
        RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID("jwt-id");
        return new JWKSet(builder.build());
    }


}
