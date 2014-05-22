package net.atos.ocsp.servlet;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import javax.servlet.ServletInputStream;

public class ServletInputStreamWrapper extends ServletInputStream {

	private ByteArrayInputStream inputStream;


	public ServletInputStreamWrapper(ByteArrayInputStream inputStream) {
		super();
		this.inputStream = inputStream;
	}


	@Override
	public int read() throws IOException {
		return inputStream.read();
	}
}
