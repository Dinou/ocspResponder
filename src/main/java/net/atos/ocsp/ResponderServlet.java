package net.atos.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ResponderServlet extends MyAbstractServlet {

	private static final long serialVersionUID = 1L;

	private final static ASN1ObjectIdentifier ID_SHA1 = new ASN1ObjectIdentifier("1.3.14.3.2.26");

	private final static ASN1ObjectIdentifier ID_NONCE = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2");

	private final static Logger logger = LoggerFactory.getLogger(ResponderServlet.class);


	@SuppressWarnings("unchecked")
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		int response = OCSPRespBuilder.INTERNAL_ERROR; // by default response as
														// ERROR
		List<RequestData> requestDataList = new ArrayList<>();
		int versionProtocol;
		ASN1OctetString OCSPNonceExtensionValue;
		logger.info("Reception d'une requete HTTP Post");
		logger.debug("Verification du type de requete : requete OCSP ?");
		checkContentType(req);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		logger.debug("Recuperation de la requete");
		IOUtils.copy(req.getInputStream(), baos);
		logger.debug("Verification de la requete recue");
		byte[] reqBytes = checkByteArray(baos);
		logger.debug("Recuperation des data de la requete");
		OCSPReq ocspreq = new OCSPReq(reqBytes);
		versionProtocol = ocspreq.getVersionNumber();
		logger.debug("Version : {}", versionProtocol);
		logger.debug("RequestExtensions :");
		List<ASN1ObjectIdentifier> extensionsList = ocspreq.getExtensionOIDs();
		for (int i = 0; i < extensionsList.size(); i++) {
			ASN1ObjectIdentifier extensionTmp = extensionsList.get(i);
			if (extensionTmp.equals(ID_NONCE)) {
				OCSPNonceExtensionValue = ocspreq.getExtension(extensionTmp).getExtnValue();
				logger.debug("NONCE : {}", OCSPNonceExtensionValue);
			}
		}
		logger.debug("RequestList :");
		setRequestData(req, requestDataList, ocspreq);
		// Get responder's certificate (public key)
		X509Certificate caOcsp;
		X509CertificateHolder[] caOcspHolder = new X509CertificateHolder[1];
		ContentSigner ocspSignKey = null;
		try {
			caOcsp = readCertificate("D:\\apacheBuild\\caOcspBC.crt");
			final byte[] encoded = caOcsp.getEncoded();
			logger.debug(new String(Hex.encode(MessageDigest.getInstance("SHA1").digest(encoded))));
			caOcspHolder[0] = new X509CertificateHolder(encoded);
		} catch (Exception e) {
			logger.debug(e.getMessage(), e);
		}
		// Get responder's private key
		PrivateKey caOcspKey = readPrivateKey("D:\\apacheBuild\\caOcspBC.pk8");
		// PrivateKey caOcspKey = readPrivateKey("D:\\apacheBuild\\ocsp.pk8");
		JcaContentSignerBuilder jca = new JcaContentSignerBuilder("SHA1withRSA");
		try {
			ocspSignKey = jca.build(caOcspKey);
		} catch (OperatorCreationException e) {
			logger.error(e.getMessage(), e);
		}
		ResponderID respondID = new ResponderID(caOcspHolder[0].getSubject());
		RespID respID = new RespID(respondID);
		BasicOCSPRespBuilder bOCSPbuilder = new BasicOCSPRespBuilder(respID);
		Date dateRevoke = new Date();
		// bOCSPbuilder.addResponse(ocspreq.getRequestList()[0].getCertID(), new
		// org.bouncycastle.cert.ocsp.UnknownStatus());
		bOCSPbuilder.addResponse(ocspreq.getRequestList()[0].getCertID(), CertificateStatus.GOOD);
		// bOCSPbuilder.addResponse(ocspreq.getRequestList()[0].getCertID(), new
		// RevokedStatus(dateRevoke,2));
		Extension ext = ocspreq.getExtension(ID_NONCE);
		bOCSPbuilder.setResponseExtensions(new Extensions(new Extension[] { ext }));
		org.bouncycastle.cert.ocsp.BasicOCSPResp respo = null;
		Date myDate = new Date(1000000);
		org.bouncycastle.cert.ocsp.OCSPResp ocspresp = null;
		try {
			respo = bOCSPbuilder.build(ocspSignKey, caOcspHolder, myDate);
			response = OCSPRespBuilder.SUCCESSFUL;
			ocspresp = new OCSPRespBuilder().build(response, respo);
		} catch (OCSPException e) {
			logger.error(e.getMessage(), e);
		}
		byte[] respBytes = ocspresp.getEncoded();
		resp.setContentType("application/ocsp-response");
		resp.setContentLength(respBytes.length);
		resp.getOutputStream().write(respBytes);
	}


	private PrivateKey readPrivateKey(String path) throws FileNotFoundException, IOException {
		PrivateKey privKey = null;
		RandomAccessFile raf = new RandomAccessFile(path, "r");
		byte[] buf = new byte[(int) raf.length()];
		raf.readFully(buf);
		raf.close();
		PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
		KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getMessage(), e);
		}
		try {
			privKey = kf.generatePrivate(kspec);
		} catch (InvalidKeySpecException e) {
			logger.error(e.getMessage(), e);
		}
		return privKey;
	}


	private byte[] checkByteArray(ByteArrayOutputStream baos) {
		byte[] reqBytes = baos.toByteArray();
		if ((reqBytes == null) || (reqBytes.length == 0)) {
			logger.error("No Request bytes");
			throw new IllegalArgumentException("No request bytes");
		}
		return reqBytes;
	}


	private void checkContentType(HttpServletRequest req) {
		String contentType = req.getHeader("Content-Type");
		if (!"application/ocsp-request".equalsIgnoreCase(contentType)) {
			logger.error("Content type is not application/ocsp-request");
			throw new IllegalArgumentException("Content type is not application/ocsp-request");
		}
	}


	private void setRequestData(HttpServletRequest req, List<RequestData> reqData, OCSPReq ocspreq) throws IOException {
		RequestData tmpReq;
		org.bouncycastle.cert.ocsp.Req[] requestList = ocspreq.getRequestList();
		if (requestList.length <= 0) {
			logger.error("No OCSP requests found");
		}
		for (int i = 0; i < requestList.length; i++) {
			BigInteger certIDs = requestList[i].getCertID().getSerialNumber();
			byte[] issuerNameHash = requestList[i].getCertID().getIssuerNameHash();
			byte[] issuerKeyHash = requestList[i].getCertID().getIssuerKeyHash();
			ASN1ObjectIdentifier algID = requestList[i].getCertID().getHashAlgOID();
			logger.debug("OCSP Request DATA : ");
			reqData.add(new RequestData());
			tmpReq = reqData.get(i);
			if (algID.equals(ID_SHA1)) {
				tmpReq.setHashAlgorithmOID(algID);
				logger.debug("   Hash Algorithm : " + "sha1");
			} else {
				logger.error("Hash not supported");
				throw new IllegalArgumentException();
			}
			tmpReq.setIssuerNameHash(issuerNameHash);
			logger.debug("   issuerNameHash : {}", getHexString(issuerNameHash));
			tmpReq.setIssuerKeyHash(issuerKeyHash);
			logger.debug("   issuerKeyHash : {}", getHexString(issuerKeyHash));
			tmpReq.setSerialNumber(certIDs);
			logger.debug("   Serial Number : {}", certIDs.intValue());
		}
	}


	private String getHexString(byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}


	private X509Certificate readCertificate(String keyFile) throws IOException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException {
		FileInputStream fis = null;
		ByteArrayInputStream bais = null;
		try {
			// use FileInputStream to read the file
			fis = new FileInputStream(keyFile);
			// read the bytes
			byte value[] = new byte[fis.available()];
			fis.read(value);
			bais = new ByteArrayInputStream(value);
			// get X509 certificate factory
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			// certificate factory can now create the certificate
			return (X509Certificate) certFactory.generateCertificate(bais);
		} finally {
			IOUtils.closeQuietly(fis);
			IOUtils.closeQuietly(bais);
		}
	}
}
