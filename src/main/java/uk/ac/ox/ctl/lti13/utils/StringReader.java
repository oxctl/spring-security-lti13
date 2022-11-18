package uk.ac.ox.ctl.lti13.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class StringReader {

	/**
	 * Read a InputStream into a String. Can use readAll() when we are on Java 9 or newer.
	 */
	public static String readString(InputStream inputStream) throws IOException {
		return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
	}
}
