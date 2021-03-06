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
	// @Test
	// public void shouldHave() throws IOException, ServletException {
	// byte[] tabEntree = { 48, 103, 48, 101, 48, 62, 48, 60, 48, 58, 48, 9, 6,
	// 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, 25, 38, 101, 57, -43, -76, -75, 24,
	// -44, 56, 43, 45, 55, 121, -53, -11, 58, 96, 97,
	// -42, 4, 20, -119, -71, 22, -123, 8, 46, -10, 95, 86, 17, -7, 101, -23,
	// 68, 34, -42, 2, -66, 39, -37, 2, 1, 10, -94, 35, 48, 33, 48, 31, 6, 9,
	// 43, 6, 1, 5, 5, 7, 48, 1, 2, 4, 18, 4,
	// 16, -92, 64, 48, -39, 115, -96, -16, -28, 76, -48, 114, 113, 72, 88, 36,
	// -39 };
	// byte[] tabSortie = { 48, -126, 3, -1, 10, 1, 0, -96, -126, 3, -8, 48,
	// -126, 3, -12, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 1, 4, -126, 3, -27, 48,
	// -126, 3, -31, 48, -127, -31, -95, 86, 48, 84, 49,
	// 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 70, 82, 49, 13, 48, 11, 6, 3, 85, 4, 8,
	// 12, 4, 78, 111, 114, 100, 49, 33, 48, 31, 6, 3, 85, 4, 10, 12, 24, 73,
	// 110, 116, 101, 114, 110, 101, 116, 32,
	// 87, 105, 100, 103, 105, 116, 115, 32, 80, 116, 121, 32, 76, 116, 100, 49,
	// 19, 48, 17, 6, 3, 85, 4, 3, 12, 10, 79, 67, 83, 80, 83, 105, 103, 110,
	// 101, 114, 24, 15, 49, 57, 55, 48, 48,
	// 49, 48, 49, 48, 48, 49, 54, 52, 48, 90, 48, 81, 48, 79, 48, 58, 48, 9, 6,
	// 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, 25, 38, 101, 57, -43, -76, -75, 24,
	// -44, 56, 43, 45, 55, 121, -53, -11, 58,
	// 96, 97, -42, 4, 20, -119, -71, 22, -123, 8, 46, -10, 95, 86, 17, -7, 101,
	// -23, 68, 34, -42, 2, -66, 39, -37, 2, 1, 10, -128, 0, 24, 15, 50, 48, 49,
	// 52, 48, 53, 50, 49, 49, 53, 50, 49,
	// 52, 55, 90, -95, 35, 48, 33, 48, 31, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 2,
	// 4, 18, 4, 16, -92, 64, 48, -39, 115, -96, -16, -28, 76, -48, 114, 113,
	// 72, 88, 36, -39, 48, 13, 6, 9, 42, -122,
	// 72, -122, -9, 13, 1, 1, 5, 5, 0, 3, -127, -127, 0, 120, -112, -53, 42,
	// -97, -56, -69, 68, -65, -37, 103, -1, 92, 21, 108, -68, 84, 53, -127, 85,
	// 88, 78, 22, 5, -88, -22, 40, -5, -86,
	// -49, -91, -109, -30, 64, -82, 11, 39, -8, 67, -90, -87, 78, 77, -75, 23,
	// -90, -10, 17, -35, 38, -112, -126, -55, 43, 66, -55, -82, -80, -109, -10,
	// -65, 9, 0, 100, 15, -50, 55, 72,
	// -38, 124, -75, -23, -87, -103, 92, 56, -19, 125, -89, -27, 78, -47, 113,
	// -76, -31, 57, -18, -74, 45, -87, -64, -83, -17, 35, -64, 124, 27, -62,
	// -78, 30, -104, 37, 38, -51, 86, 54,
	// -91, -126, -118, -83, 17, 6, -69, -42, 64, -112, -60, 70, 101, 87, -111,
	// -47, -45, -104, -26, -38, 63, -6, -96, -126, 2, 102, 48, -126, 2, 98, 48,
	// -126, 2, 94, 48, -126, 1, -57, -96,
	// 3, 2, 1, 2, 2, 9, 0, -31, -95, -9, 86, -21, -85, 85, 66, 48, 13, 6, 9,
	// 42, -122, 72, -122, -9, 13, 1, 1, 5, 5, 0, 48, 84, 49, 11, 48, 9, 6, 3,
	// 85, 4, 6, 19, 2, 70, 82, 49, 13, 48, 11,
	// 6, 3, 85, 4, 8, 12, 4, 78, 111, 114, 100, 49, 33, 48, 31, 6, 3, 85, 4,
	// 10, 12, 24, 73, 110, 116, 101, 114, 110, 101, 116, 32, 87, 105, 100, 103,
	// 105, 116, 115, 32, 80, 116, 121, 32,
	// 76, 116, 100, 49, 19, 48, 17, 6, 3, 85, 4, 3, 12, 10, 79, 67, 83, 80, 83,
	// 105, 103, 110, 101, 114, 48, 30, 23, 13, 49, 52, 48, 53, 49, 53, 49, 51,
	// 49, 49, 51, 52, 90, 23, 13, 49, 53,
	// 48, 53, 49, 53, 49, 51, 49, 49, 51, 52, 90, 48, 84, 49, 11, 48, 9, 6, 3,
	// 85, 4, 6, 19, 2, 70, 82, 49, 13, 48, 11, 6, 3, 85, 4, 8, 12, 4, 78, 111,
	// 114, 100, 49, 33, 48, 31, 6, 3, 85,
	// 4, 10, 12, 24, 73, 110, 116, 101, 114, 110, 101, 116, 32, 87, 105, 100,
	// 103, 105, 116, 115, 32, 80, 116, 121, 32, 76, 116, 100, 49, 19, 48, 17,
	// 6, 3, 85, 4, 3, 12, 10, 79, 67, 83, 80,
	// 83, 105, 103, 110, 101, 114, 48, -127, -97, 48, 13, 6, 9, 42, -122, 72,
	// -122, -9, 13, 1, 1, 1, 5, 0, 3, -127, -115, 0, 48, -127, -119, 2, -127,
	// -127, 0, -58, 15, 93, -7, -105, 36,
	// 111, -34, -42, 113, 125, -117, 93, 66, -128, 13, -37, 42, 22, 75, 13, 76,
	// -83, 89, 83, -116, 47, -117, -128, -91, 101, 99, 86, 88, 66, 3, 41, -17,
	// -45, -58, 126, 23, 72, 28, 112, 34,
	// 123, 96, 92, -80, -90, 45, -39, 24, -14, 107, -18, 77, 65, -25, -60, -79,
	// 49, 41, 70, 114, -1, -20, 93, 97, -1, -37, -40, -42, -88, 27, 106, -122,
	// -36, 111, -107, -96, 66, 27, 24,
	// 105, 60, -32, -67, 65, 7, -2, -112, 73, -19, -75, 112, -95, -10, 10, -26,
	// 16, 6, 108, 2, -42, -117, -57, 9, -122, 95, -30, 118, 77, 56, 41, -72, 5,
	// 99, 12, -53, 57, 14, -57, 23, 91,
	// -44, -127, 2, 3, 1, 0, 1, -93, 56, 48, 54, 48, 18, 6, 3, 85, 29, 19, 1,
	// 1, -1, 4, 8, 48, 6, 1, 1, -1, 2, 1, 0, 48, 11, 6, 3, 85, 29, 15, 4, 4, 3,
	// 2, 5, -32, 48, 19, 6, 3, 85, 29, 37,
	// 4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 9, 48, 13, 6, 9, 42, -122, 72,
	// -122, -9, 13, 1, 1, 5, 5, 0, 3, -127, -127, 0, -92, 112, -90, 118, 8, 28,
	// 94, -86, -98, -128, 4, -111, 57,
	// 99, -98, 109, 29, -74, 24, -53, 24, 75, -121, 94, 123, 75, -61, -54, -24,
	// 0, 82, -87, -84, -4, -123, 25, -88, -29, -89, -11, -83, -27, 15, 108,
	// -71, 101, -6, 19, 71, 44, -119, -9, 55,
	// -26, 84, 13, -98, -102, -113, 109, 47, 70, 70, 108, 25, 119, -111, -112,
	// -31, -9, 41, -106, -46, 48, -69, 55, -114, -23, 117, -88, 47, -115, -41,
	// -68, -51, -47, 110, 4, -103, 61, 97,
	// 109, -39, 93, -67, 17, -12, -57, -13, 82, -8, 74, 13, -88, -63, -15, 119,
	// 32, -62, -59, 20, -85, -5, 102, -49, -95, 64, 83, 98, -34, 34, -89, -92,
	// -115, -123, 103, 72, -92 };
	// ServletInputStream input = new ServletInputStreamWrapper(new
	// ByteArrayInputStream(tabEntree));
	// ServletOutputStream output = mock(ServletOutputStream.class);
	// when(request.getInputStream()).thenReturn(input);
	// when(request.getHeader("Content-Type")).thenReturn("application/ocsp-request");
	// when(request.getQueryString()).thenReturn("DINOU");
	// when(response.getOutputStream()).thenReturn(output);
	// servlet.doPost(request, response);
	// verify(output, times(1)).write(tabSortie);
	// }
}
