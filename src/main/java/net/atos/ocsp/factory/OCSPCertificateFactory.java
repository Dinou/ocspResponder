package net.atos.ocsp.factory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
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
import net.atos.ocsp.data.OCSPCertificate;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OCSPCertificateFactory {

	private static final String OCSP_CERTIFICATE_PK_PATH = "certificates/caOcspBasicConstraints.pk8";

	private static final String OCSP_CERTIFICATE_PATH = "certificates/caOcspBasicConstraints.crt";

	private final static Logger logger = LoggerFactory.getLogger(OCSPCertificateFactory.class);


	public static OCSPCertificate getOCSPCertificate() throws FileNotFoundException, IOException {
		OCSPCertificate retour = new OCSPCertificate();
		X509Certificate caOcsp;
		X509CertificateHolder[] caOcspHolder = new X509CertificateHolder[1];
		ContentSigner ocspSignKey = null;
		try {
			caOcsp = readCertificate(OCSP_CERTIFICATE_PATH);
			final byte[] encoded = caOcsp.getEncoded();
			logger.debug(new String(Hex.encode(MessageDigest.getInstance("SHA1").digest(encoded))));
			caOcspHolder[0] = new X509CertificateHolder(encoded);
		} catch (Exception e) {
			logger.debug(e.getMessage(), e);
		}
		// Get responder's private key
		PrivateKey caOcspKey = readPrivateKey(OCSP_CERTIFICATE_PK_PATH);
		JcaContentSignerBuilder jca = new JcaContentSignerBuilder("SHA1withRSA");
		try {
			ocspSignKey = jca.build(caOcspKey);
		} catch (OperatorCreationException e) {
			logger.error(e.getMessage(), e);
		}
		retour.setCertificateChain(caOcspHolder);
		retour.setSigner(ocspSignKey);
		return retour;
	}


	private static PrivateKey readPrivateKey(String path) throws FileNotFoundException, IOException {
		PrivateKey privKey = null;
		InputStream pk8InputStream = OCSPCertificateFactory.class.getClassLoader().getResourceAsStream(path);
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		IOUtils.copy(pk8InputStream, buffer);
		PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buffer.toByteArray());
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


	private static X509Certificate readCertificate(String keyFileClassPath) throws IOException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException {
		InputStream fis = null;
		ByteArrayInputStream bais = null;
		try {
			// use FileInputStream to read the file
			fis = OCSPCertificateFactory.class.getClassLoader().getResourceAsStream(keyFileClassPath);
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
