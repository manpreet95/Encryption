package com.asymmetricencryption.PublicKeyEncryption;

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
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class EncryptionImpl implements Encryption {

	/*
	 * returns key pair (public-private key) from the keystore
	 */
	@Override
	public KeyPair getKeyPair(String keyStorePath, String keyStoreType, char[] password, String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		
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
	public PublicKey getPublicKey(String publicKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {
		
		File publicKeyFile = new File(publicKeyPath);
		
		FileInputStream fis = new FileInputStream(publicKeyFile);
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fis);
		PublicKey publicKey = certificate.getPublicKey();
		
		return publicKey;
	}



	@Override
	public String encryptData(String plainText, PublicKey publicKey, String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		
		byte[] cipherText = cipher.doFinal(plainText.getBytes());
		
		byte[] encodedCipherText = Base64.getEncoder().encode(cipherText);
		
		return new String(encodedCipherText);
	}



	@Override
	public String decryptData(String encodedCipherText, PrivateKey privateKey, String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		
		byte[] cipherText = Base64.getDecoder().decode(encodedCipherText);
		
		byte[] plainText = cipher.doFinal(cipherText);
		
		return new String(plainText);
	}
}
