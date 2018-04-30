/*
 * 1. Fetch the private key from keystore
 * 2. Generate digital signature
 * 3. Send signature and public key
 * 4. Verify the digital signature
 * 
 * */
package com.asymmetricencryption.digitalsignature;

import java.security.PrivateKey;
import java.security.PublicKey;

public class Tester {
	
	public static void main(String args[]) throws Exception {
				
		String keyStorePath = "D:/Work/KeyStore/keystore.jks";
		String keyStoreType = "JCEKS";
		char[] password = "123456789".toCharArray();
		String alias = "demo";
		
		
		DigitalSignature ds = new DigitalSignatureImpl();
		
//		KeyPair keyPair = ds.getKeyPair(keyStorePath, keyStoreType, password, alias);
		
		//get private key
		PrivateKey privateKey = ds.getPrivateKey(keyStorePath, keyStoreType, password, alias);
		
		String plainText = "Hello World";
		String algorithm = "SHA1withDSA";
		
		//generate the digital signature
		String encodedCipherText = ds.generateDigitalSignature(plainText, algorithm, privateKey);
		
		String publicKeyPath = "D:/Work/KeyStore/demoPublicKey.cer";
		//retrieve public key
		PublicKey publicKey = ds.getPublicKey(publicKeyPath, algorithm);
		
		//verify the digital signature
		ds.verifyDigitalSignature(plainText, encodedCipherText, algorithm, publicKey);
		
	}
}
