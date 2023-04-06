package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

/**
 * This is for when we fail to find a client registration.
 */
class InvalidClientRegistrationIdException extends IllegalArgumentException {

	/**
	 * @param message the exception message
	 */
	InvalidClientRegistrationIdException(String message) {
		super(message);
	}

}
