package com.asymmetricencryption.digitalsignature;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class DigitalSignatureImpl implements DigitalSignature {
	
	/*
	 * returns key pair (public-private key) from the keystore
	 */
	@Override
	public KeyPair getKeyPair(String keyStorePath, String keyStoreType, char[] password, String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		
		System.out.println("********** Get key pair **********");
		
		FileInputStream fis = new FileInputStream(keyStorePath);
		
		KeyStore keyStore = KeyStore.getInstance(keyStoreType);
		keyStore.load(fis, password);
		
		KeyPair keyPair = null;
		
		Key key = keyStore.getKey(alias, password);
		
		if(key instanceof PrivateKey) {
			Certificate certificate = keyStore.getCertificate(alias);	
			PublicKey publicKey = certificate.getPublicKey();
			keyPair = new KeyPair(publicKey, (PrivateKey) key);
		}
		
		return keyPair;
	}
	
	
	
	/*
	 * returns the private key from the keystore
	 */
	@Override
	public PrivateKey getPrivateKey(String keyStorePath, String keyStoreType, char[] password, String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		
		System.out.println("********** Get Private Key **********");
		
		FileInputStream fis = new FileInputStream(keyStorePath);
		
		KeyStore keyStore = KeyStore.getInstance(keyStoreType);
		keyStore.load(fis, password);
		
		Key key = keyStore.getKey(alias, password);
		
		return (PrivateKey)key;
	}
	
	
	
	
	/*
	 * returns the public key from certificate
	 */
	@Override
	public PublicKey getPublicKey(String publicKeyPath, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {
		
		System.out.println("********** Get Public Key **********");
		
		File publicKeyFile = new File(publicKeyPath);
		
		FileInputStream fis = new FileInputStream(publicKeyFile);
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fis);
		PublicKey publicKey = certificate.getPublicKey();
		
		return publicKey;
	}
	
	
	
	
	/*
	 * returns the digital signature generated by the plain text
	 */
	@Override
	public String generateDigitalSignature(String plainText, String algorithm, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		
		System.out.println("---------------------------------------------------------------------------------------");
		System.out.println("********** Digital signature generation **********");
		
		Signature signature = Signature.getInstance(algorithm);
		
		signature.initSign(privateKey);
		signature.update(plainText.getBytes());
		byte[] cipherText = signature.sign();
		
		System.out.println("Encrypted Text: "+cipherText);
		
		String encodedCipherText = Base64.getEncoder().encodeToString(cipherText);
		
		System.out.println("Encoded Text: "+encodedCipherText);
		System.out.println("---------------------------------------------------------------------------------------");
		
		return encodedCipherText;
	}
	
	
	
	
	/*
	 * checks the validity of the digital signature received in parameters and returns true or false accordingly
	 */
	@Override
	public Boolean verifyDigitalSignature(String plainText, String encodedCipherText, String algorithm, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException, IOException {
		
		System.out.println("---------------------------------------------------------------------------------------");
		System.out.println("********** Digital signature verification **********");
		
		Signature signature = Signature.getInstance(algorithm);
		
		
		
		signature.initVerify(publicKey);
		signature.update(plainText.getBytes());
		
		System.out.println("Encoded Cipher Text:"+encodedCipherText);
		
		byte[] cipherText = Base64.getDecoder().decode(encodedCipherText);
		
		System.out.println("Cipher Text"+cipherText);
		
		Boolean isValid = signature.verify(cipherText);
		
		System.out.println("Valid signature? "+isValid);
		System.out.println("---------------------------------------------------------------------------------------");
		
		return isValid;
	}
	
}
