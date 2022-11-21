package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface AuthorizationRedirectHandler {
	
	/**
	 * Send a redirect to the user to start authorization but make the authorization request available.
	 * @param request The HttpServletRequest that came in.
	 * @param response The HttpServletResponse that we are writing the output to.
	 * @param authorizationRequest Details of the OAuth request.   
	 */
	void sendRedirect(HttpServletRequest request, HttpServletResponse response, OAuth2AuthorizationRequest authorizationRequest) throws IOException;

}
