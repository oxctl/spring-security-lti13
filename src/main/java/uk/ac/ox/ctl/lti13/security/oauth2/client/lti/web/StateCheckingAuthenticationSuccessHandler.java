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

import com.fasterxml.jackson.core.io.JsonStringEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationTargetUrlRequestHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.authentication.OidcAuthenticationToken;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * This is needed so that we can pass the state value to the client(browser) to allow it to check if it matches the
 * value saved at the start of the login.
 *
 * @author Matthew Buckett
 */
public class StateCheckingAuthenticationSuccessHandler extends
		AbstractAuthenticationTargetUrlRequestHandler implements
		AuthenticationSuccessHandler {

	private final boolean useState;

	/**
	 * @param useState if true then use the state parameter for tracking logins.
	 */
	public StateCheckingAuthenticationSuccessHandler(boolean useState) {
		this.useState = useState;
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
		
		if (!useState) {
			super.handle(request, response, authentication);
			return;
		}
		String targetUrl = determineTargetUrl(request, response, authentication);

		if (response.isCommitted()) {
			logger.debug("Response has already been committed. Unable to redirect to "
					+ targetUrl);
			return;
		}

		if (!(authentication instanceof OidcAuthenticationToken)) {
			logger.debug("Authentication should be OidcAuthenticationToken. Unable to redirect to "
					+ targetUrl);
			return;
		}
		OidcAuthenticationToken oidcAuthenticationToken = (OidcAuthenticationToken) authentication;
		String state = oidcAuthenticationToken.getState();


		JsonStringEncoder encoder = JsonStringEncoder.getInstance();
		response.setContentType("text/html");
		PrintWriter writer = response.getWriter();
		writer.append("<html><head><title>redirect</title><script>");
		writer.append("var state = \"" + new String(encoder.quoteAsString(state)) + "\";\n");
		writer.append("var url = \"" + new String(encoder.quoteAsString(targetUrl)) + "\";\n");
		writer.append("try {\n" +
				"    if (state !== window.sessionStorage.getItem('state')) {\n" +
				"     console.log('State does not match');\n" +
				"    } else {\n" +
				"         document.location = url;\n" +
				"    } \n" +
				"} catch (error) {\n" +
				"    if (error.name === 'SecurityError' ) {\n" +
				"        console.log(\"You have cookies disabled for this site.\")\n" +
				"    } else {\n" +
				"        throw error;\n" +
				"    }\n" +
				"}");
		writer.append("</script></head><body>");

	}

	/**
	 * Removes temporary authentication-related data which may have been stored in the
	 * session during the authentication process.
	 */
	protected final void clearAuthenticationAttributes(HttpServletRequest request) {
		HttpSession session = request.getSession(false);

		if (session == null) {
			return;
		}

		session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
	}
}
