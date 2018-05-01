package com.asymmetricencryption.PublicKeyEncryption;

import java.security.PrivateKey;
import java.security.PublicKey;

public class Tester {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		Encryption encryption = new EncryptionImpl();
		
		String keyStorePath = "D:/Work/KeyStore/keystore.jks";
		String keyStoreType = "JCEKS";
		char[] password = "123456789".toCharArray();
		String alias = "demoRSA";
		
		String publicKeyPath = "D:/Work/KeyStore/demoRSAPublicKey.cer";
		String algorithm = "RSA";
		
		String plainText = "Hello World";
		System.out.println("Original Plain text: "+plainText);
		
		//fetch public key
		PublicKey publicKey = encryption.getPublicKey(publicKeyPath);
		
		//encrypt data
		String encodedCipherText = encryption.encryptData(plainText, publicKey, algorithm);
		
		System.out.println("Encoded cipher Text: "+new String(encodedCipherText));
		
		//fetch private key
		PrivateKey privateKey = encryption.getPrivateKey(keyStorePath, keyStoreType, password, alias);
		
		//decrypt data
		String result = encryption.decryptData(encodedCipherText, privateKey, algorithm);
		System.out.println("Decrypted Plain Text: "+result);
		
	}

}
