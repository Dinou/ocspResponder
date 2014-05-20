package net.atos.ocsp.data;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;


public class OCSPCertificate {
	
	private X509CertificateHolder[] certificateChain;
	
	private ContentSigner signer;

	
	public X509CertificateHolder[] getCertificateChain() {
		return certificateChain;
	}

	
	public void setCertificateChain(X509CertificateHolder[] certificateChain) {
		this.certificateChain = certificateChain;
	}

	
	public ContentSigner getSigner() {
		return signer;
	}

	
	public void setSigner(ContentSigner signer) {
		this.signer = signer;
	}
	
	
	
	
}
