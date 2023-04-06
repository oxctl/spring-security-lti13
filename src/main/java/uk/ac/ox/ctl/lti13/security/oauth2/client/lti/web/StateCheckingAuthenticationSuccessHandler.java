package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationTargetUrlRequestHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.authentication.OidcAuthenticationToken;
import uk.ac.ox.ctl.lti13.utils.StringReader;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * This is needed so that we can pass the state value to the client(browser) to allow it to check if it matches the
 * value saved at the start of the login.
 *
 * @author Matthew Buckett
 * @see StateAuthorizationRedirectHandler
 */
public class StateCheckingAuthenticationSuccessHandler extends
		AbstractAuthenticationTargetUrlRequestHandler implements
		AuthenticationSuccessHandler {

	private final OptimisticAuthorizationRequestRepository authorizationRequestRepository;
	private final String htmlTemplate;
	
	private String name = "/uk/ac/ox/ctl/lti13/step-3-redirect.html";

	/**
	 * @param authorizationRequestRepository The repository holding authorization requests
	 */
	public StateCheckingAuthenticationSuccessHandler(OptimisticAuthorizationRequestRepository authorizationRequestRepository) {
		this.authorizationRequestRepository = authorizationRequestRepository;
		try {
			htmlTemplate = StringReader.readString(getClass().getResourceAsStream(name));
		} catch (IOException e) {
			throw new IllegalStateException("Failed to read " + name, e);
		}
	}

	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Calls the parent class {@code handle()} method to forward or redirect to the target
	 * URL, and then calls {@code clearAuthenticationAttributes()} to remove any leftover
	 * session data.
	 */
	public void onAuthenticationSuccess(HttpServletRequest request,
										HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {

		handle(request, response, authentication);
		clearAuthenticationAttributes(request);
	}

	protected void handle(HttpServletRequest request, HttpServletResponse response,
						  Authentication authentication) throws IOException, ServletException {
		
		// If we got this from the Session then just redirect
		if (authorizationRequestRepository.hasWorkingSession(request)) {
			super.handle(request, response, authentication);
			return;
		}
		String targetUrl = determineTargetUrl(request, response, authentication);

		if (response.isCommitted()) {
			logger.debug("Response has already been committed. Unable to redirect to "
					+ targetUrl);
			return;
		}

		if (!(authentication instanceof OidcAuthenticationToken oidcAuthenticationToken)) {
			logger.debug("Authentication should be OidcAuthenticationToken. Unable to redirect to "
					+ targetUrl);
			return;
		}
        String state = oidcAuthenticationToken.getState();
		String nonce = ((OidcUser)(oidcAuthenticationToken).getPrincipal()).getIdToken().getNonce();

		response.setContentType("text/html;charset=UTF-8");
		PrintWriter writer = response.getWriter();
		writer.append(htmlTemplate
				.replaceFirst("@@state@@", state)
				.replaceFirst("@@url@@", targetUrl)
				.replaceFirst("@@nonce@@", nonce)
		);
	}

	/**
	 * Removes temporary authentication-related data which may have been stored in the
	 * session during the authentication process.
	 * @param request The HttpServletRequest to clear the authentication from.
	 */
	protected final void clearAuthenticationAttributes(HttpServletRequest request) {
		HttpSession session = request.getSession(false);

		if (session == null) {
			return;
		}

		session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
	}
}
