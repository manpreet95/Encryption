package com.asymmetricencryption.digitalsignatureusingcipher;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface DigitalSignature {
	
	KeyPair getKeyPair(String keyStorePath, String keyStoreType, char[] password, String alias) throws Exception;
	
	PrivateKey getPrivateKey(String keyStorePath, String keyStoreType, char[] password, String alias) throws Exception;
	
	PublicKey getPublicKey(String publicKeyPath) throws Exception;
	
	String generateDigitalSignature(String plainText, String algorithm, PrivateKey privateKey) throws Exception;
	
	Boolean verifyDigitalSignature(String plainText, String encodedCipherText, String algorithm, PublicKey publicKey) throws Exception;
}
