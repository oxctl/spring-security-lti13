package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;


public class PathOIDCInitiationRegistrationResolver implements OIDCInitiationRegistrationResolver {

    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

    private final PathPatternRequestMatcher authorizationRequestMatcher;

    public PathOIDCInitiationRegistrationResolver(String authorizationRequestBaseUri) {
        Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
        this.authorizationRequestMatcher = PathPatternRequestMatcher.withDefaults()
                .matcher(authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
    }

    @Override
    public String resolve(HttpServletRequest request) {
        RequestMatcher.MatchResult matchResult = this.authorizationRequestMatcher.matcher(request);
        if (matchResult.isMatch()) {
            return matchResult.getVariables().get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }

}
