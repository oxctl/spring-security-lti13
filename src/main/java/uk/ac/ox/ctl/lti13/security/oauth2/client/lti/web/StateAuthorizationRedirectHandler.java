package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import com.fasterxml.jackson.core.io.JsonStringEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import uk.ac.ox.ctl.lti13.utils.StringReader;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @see StateCheckingAuthenticationSuccessHandler
 */
public class StateAuthorizationRedirectHandler implements AuthorizationRedirectHandler {

	private Logger logger = LoggerFactory.getLogger(StateAuthorizationRedirectHandler.class);

	private final JsonStringEncoder encoder = JsonStringEncoder.getInstance();
	private final String htmlTemplate;

	private String name = "/uk/ac/ox/ctl/lti13/step-1-redirect.html";

	public StateAuthorizationRedirectHandler() {
		try {
			htmlTemplate = StringReader.readString(getClass().getResourceAsStream(name));
		} catch (IOException e) {
			throw new IllegalStateException("Failed to read "+ name, e);
		}
	}

	public void setName(String name) {
		this.name = name;
	}

	/**
	 * This sends the user off, but before that it saves data in the user's browser's sessionStorage so that
	 * when they come back we can check that noting malicious is going on.
	 */
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, OAuth2AuthorizationRequest authorizationRequest) throws IOException {
		String url = authorizationRequest.getAuthorizationRequestUri();
		if (response.isCommitted()) {
			logger.debug("Response has already been committed. Unable to redirect to " + url);
			return;
		}
		String state = new String(encoder.quoteAsString(authorizationRequest.getState()));
		response.setContentType("text/html;charset=UTF-8");
		PrintWriter writer = response.getWriter();
		writer.append(htmlTemplate.replaceFirst("@@state@@", state).replaceFirst("@@url@@", url));
	}
}