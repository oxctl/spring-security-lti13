package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.io.IOException;

public interface AuthorizationRedirectHandler {
	
	/**
	 * Send a redirect to the user to start authorization but make the authorization request available.
	 * @param request The HttpServletRequest that came in.
	 * @param response The HttpServletResponse that we are writing the output to.
	 * @param authorizationRequest Details of the OAuth request.
	 * @throws IOException If there's a IO problem sending the redirect.   
	 */
	void sendRedirect(HttpServletRequest request, HttpServletResponse response, OAuth2AuthorizationRequest authorizationRequest) throws IOException;

}
