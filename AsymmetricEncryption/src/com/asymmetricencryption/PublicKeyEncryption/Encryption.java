package com.asymmetricencryption.PublicKeyEncryption;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface Encryption {
	
	KeyPair getKeyPair(String keyStorePath, String keyStoreType, char[] password, String alias) throws Exception;
	
	PrivateKey getPrivateKey(String keyStorePath, String keyStoreType, char[] password, String alias) throws Exception;
	
	PublicKey getPublicKey(String publicKeyPath) throws Exception;

	String encryptData(String plainText, PublicKey publicKey, String algorithm) throws Exception;
	
	String decryptData(String encodedCipherText, PrivateKey privateKey, String algorithm) throws Exception;
}
