package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

public class PathOIDCInitiationRegistrationResolver implements OIDCInitiationRegistrationResolver {
    
    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

    private final AntPathRequestMatcher authorizationRequestMatcher;

    public PathOIDCInitiationRegistrationResolver(String authorizationRequestBaseUri) {
        Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
        this.authorizationRequestMatcher = new AntPathRequestMatcher(
                authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
    }

    @Override
    public String resolve(HttpServletRequest request) {
        if (this.authorizationRequestMatcher.matches(request)) {
            return this.authorizationRequestMatcher
                    .extractUriTemplateVariables(request).get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }

}
