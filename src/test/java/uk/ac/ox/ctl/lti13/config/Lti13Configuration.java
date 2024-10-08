package uk.ac.ox.ctl.lti13.config;

import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestOperations;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import uk.ac.ox.ctl.lti13.Lti13Configurer;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web.LTIAuthorizationGrantType;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@Configuration
@EnableWebSecurity
@EnableWebMvc
public class Lti13Configuration {

    @Bean
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests().anyRequest().authenticated();
        Lti13Configurer lti13Configurer = new Lti13Configurer();
        http.apply(lti13Configurer);
        return http.build();
    }

    @Bean
    public KeyPair keyPair() throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance("RSA").generateKeyPair();
    }

    @Bean
    public RestOperations restOperations() {
        return Mockito.mock(RestOperations.class);
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        String platformUri = "https://platform.test/";

        ClientRegistration client = ClientRegistration.withRegistrationId("test")
                .clientId("test-id")
                .authorizationGrantType(LTIAuthorizationGrantType.IMPLICIT)
                .scope("openid")
                .redirectUri("{baseUrl}/lti/login")
                .authorizationUri(platformUri+ "/auth/new")
                .tokenUri(platformUri+ "/access_tokens")
                .jwkSetUri(platformUri+ "/keys.json")
                .build();
        return new InMemoryClientRegistrationRepository(client);
    }
}


