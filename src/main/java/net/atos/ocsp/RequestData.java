package net.atos.ocsp;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;

public class RequestData {
	private ASN1ObjectIdentifier HashAlgorithmOID ;
	private byte[] IssuerNameHash ;
	private byte[] IssuerKeyHash ;
	private BigInteger SerialNumber ;
	
	
	public RequestData(){
		
	}
	
	public RequestData( ASN1ObjectIdentifier hashAlgoOID, byte[] issuerNameHash, byte[] issuerKeyHash, BigInteger serialNumber){
		
		this.HashAlgorithmOID = hashAlgoOID ;
		this.IssuerNameHash = issuerNameHash ;
		this.IssuerKeyHash = issuerKeyHash ;
		this.SerialNumber = serialNumber ;
	
	}

	
	

	public ASN1ObjectIdentifier getHashAlgorithmOID() {
		return HashAlgorithmOID;
	}

	public void setHashAlgorithmOID(ASN1ObjectIdentifier hashAlgorithmOID) {
		HashAlgorithmOID = hashAlgorithmOID;
	}

	public byte[] getIssuerNameHash() {
		return IssuerNameHash;
	}

	public void setIssuerNameHash(byte[] issuerNameHash) {
		IssuerNameHash = issuerNameHash;
	}

	public byte[] getIssuerKeyHash() {
		return IssuerKeyHash;
	}

	public void setIssuerKeyHash(byte[] issuerKeyHash) {
		IssuerKeyHash = issuerKeyHash;
	}

	public BigInteger getSerialNumber() {
		return SerialNumber;
	}

	public void setSerialNumber(BigInteger serialNumber) {
		SerialNumber = serialNumber;
	}
}

