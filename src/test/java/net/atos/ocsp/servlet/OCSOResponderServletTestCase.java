package net.atos.ocsp.servlet;

import static org.assertj.core.api.Assertions.assertThat;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class OCSOResponderServletTestCase {

	private ResponderServlet servlet = new ResponderServlet();

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;


	@Before
	public void initTest() throws ServletException {
		System.out.println("init !");
		servlet.init();
	}


	@Test(expected = IllegalArgumentException.class)
	public void shouldGetIllegalArgumentException() throws ServletException, IOException {
		servlet.doPost(request, response);
	}


	@Test
	public void shouldGetIllegalArgumentExceptionµWithSpecificMessage() throws ServletException, IOException {
		try {
			servlet.doPost(request, response);
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("Content type is not application/ocsp-request");
		}
	}
}
