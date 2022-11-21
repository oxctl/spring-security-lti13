package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Checks to see if we already have a valid HTTP Session containing a token, if so we store details of the login
 * in the HTTP Session, otherwise we use store based on the state.
 */
public class OptimisticAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    
    private final String SESSION_FLAG = OptimisticAuthorizationRequestRepository.class.getName()+".FLAG";

    private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> sessionBased;
    private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> stateBased;

    public OptimisticAuthorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> sessionBased, AuthorizationRequestRepository<OAuth2AuthorizationRequest> stateBased) {
        this.sessionBased = sessionBased;
        this.stateBased = stateBased;
    }
    
    public boolean hasPersistentSession(HttpServletRequest request) {
        // Check that we have successfully stored the state in the session before.
        HttpSession session = request.getSession(false);
        return session != null && session.getAttribute(SESSION_FLAG) != null;
    }
    
    public void setPersistentSession(HttpServletRequest request, boolean valid) {
        HttpSession session = request.getSession();
        if (valid) {
            session.setAttribute(SESSION_FLAG, true);
        } else {
            session.removeAttribute(SESSION_FLAG);
        }
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = sessionBased.loadAuthorizationRequest(request);
        if (oAuth2AuthorizationRequest != null) {
            // If we got the request successfully from the session we should use it in the future.
            setPersistentSession(request, true);
            return oAuth2AuthorizationRequest;
        }
        return stateBased.loadAuthorizationRequest(request);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if (!hasPersistentSession(request)) {
            stateBased.saveAuthorizationRequest(authorizationRequest, request, response);
        }
        sessionBased.saveAuthorizationRequest(authorizationRequest, request, response);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
        OAuth2AuthorizationRequest stateRequest = stateBased.removeAuthorizationRequest(request);
        OAuth2AuthorizationRequest sessionRequest =  sessionBased.removeAuthorizationRequest(request);
        // Prioritise the one from the session if it's not null.
        if (sessionRequest != null) {
            setPersistentSession(request, true);
            return sessionRequest;
        } 
        return stateRequest;
    }
}
