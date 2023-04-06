package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Checks to see if we already have a valid HTTP Session containing a token, if so we store details of the login
 * in the HTTP Session, otherwise we use store based on the state.
 */
public class OptimisticAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String ATTRIBUTE_NAME = OptimisticAuthorizationRequestRepository.class.getName() + "#WORKING_SESSION";
    private final String COOKIE_NAME = "WORKING_COOKIES";

    private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> sessionBased;
    private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> stateBased;

    public OptimisticAuthorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> sessionBased, AuthorizationRequestRepository<OAuth2AuthorizationRequest> stateBased) {
        this.sessionBased = sessionBased;
        this.stateBased = stateBased;
    }

    public boolean hasWorkingSession(HttpServletRequest request) {
        // We don't want to wait for the next request to use the session, so as well as looking for cookies we
        // check for an attribute on the request.
        if (request.getAttribute(ATTRIBUTE_NAME) != null) {
            return true;
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (COOKIE_NAME.equals(cookie.getName())) {
                    return true;
                }
            }
        }
        return false;
    }

    public void setWorkingSession(HttpServletRequest request, HttpServletResponse response) {
        // We set our own cookie here because the session is only limited to a short period of time
        // but we would like to use a session even after the original has expired.
        Cookie cookie = new Cookie(COOKIE_NAME, "true");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        // Set the cookie for 1 year.
        // TODO This should be configurable.
        cookie.setMaxAge(60 * 60 * 24 * 356);
        response.addCookie(cookie);
        // Mark the current request as having a working session.
        request.setAttribute(ATTRIBUTE_NAME, true);
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = sessionBased.loadAuthorizationRequest(request);
        if (oAuth2AuthorizationRequest != null) {
            return oAuth2AuthorizationRequest;
        }
        return stateBased.loadAuthorizationRequest(request);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if (!hasWorkingSession(request)) {
            stateBased.saveAuthorizationRequest(authorizationRequest, request, response);
        }
        sessionBased.saveAuthorizationRequest(authorizationRequest, request, response);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizationRequest stateRequest = stateBased.removeAuthorizationRequest(request, response);
        OAuth2AuthorizationRequest sessionRequest = sessionBased.removeAuthorizationRequest(request, response);
        // Prioritise the one from the session if it's not null.
        if (sessionRequest != null) {
            // Mark that we got the state from the cookie.
            setWorkingSession(request, response);
            return sessionRequest;
        }
        return stateRequest;
    }
}
