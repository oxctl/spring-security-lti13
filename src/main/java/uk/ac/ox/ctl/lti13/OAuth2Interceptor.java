package uk.ac.ox.ctl.lti13;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.io.IOException;
import java.time.Instant;

public class OAuth2Interceptor implements ClientHttpRequestInterceptor {

    private OAuth2AccessToken accessToken;

    public OAuth2Interceptor(OAuth2AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    public String getAccessTokenValue() {
        return accessToken.getTokenValue();
    }

    public boolean isValid() {
        return accessToken.getExpiresAt() != null && Instant.now().isBefore(accessToken.getExpiresAt());
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        String accessToken = getAccessTokenValue();
        request.getHeaders().setBearerAuth(accessToken);
        return execution.execute(request, body);
    }
}
