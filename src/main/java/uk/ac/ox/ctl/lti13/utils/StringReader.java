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
	 * @param inputStream The InputStream to read from.
	 * @throws IOException If there's problem reading from the input.
	 * @return The String contents of the stream.
	 */
	public static String readString(InputStream inputStream) throws IOException {
		StringBuilder textBuilder = new StringBuilder();
		try (Reader reader = new BufferedReader(new InputStreamReader
				(inputStream, Charset.forName(StandardCharsets.UTF_8.name())))) {
			char[] buffer = new char[1024];
			int len;
			while ((len = reader.read(buffer)) != -1) {
				textBuilder.append(buffer, 0, len);
			}
		}
		return textBuilder.toString();
	}
}
