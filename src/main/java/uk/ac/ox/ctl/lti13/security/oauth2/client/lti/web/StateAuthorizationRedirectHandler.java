package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import com.fasterxml.jackson.core.io.JsonStringEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class StateAuthorizationRedirectHandler implements AuthorizationRedirectHandler {

	private Logger logger = LoggerFactory.getLogger(StateAuthorizationRedirectHandler.class);

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
		JsonStringEncoder encoder = JsonStringEncoder.getInstance();
		String state = authorizationRequest.getState();
		response.setContentType("text/html");
		PrintWriter writer = response.getWriter();
		writer.append("<html><head><title>redirect</title><script>");
		writer.append("var state = \""+ new String(encoder.quoteAsString(state)) + "\";");
		writer.append("var url = \""+ new String(encoder.quoteAsString(url)) + "\";");
		writer.append("try {\n" +
				"    window.sessionStorage.setItem('state', state);\n" +
				"} catch (error) {\n" +
				"    if (error.name === 'SecurityError' ) {\n" +
				"        console.log(\"You have cookies disabled for this site.\");\n" +
				"    } else {\n" +
				"        throw error;\n" +
				"    }\n" +
				"}");
		writer.append("document.location = url;");
		writer.append("</script></head><body>");
		writer.append("</body></html>");
	}

}
