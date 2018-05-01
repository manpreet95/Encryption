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
		System.out.println("Fecthing private key");
		PrivateKey privateKey = ds.getPrivateKey(keyStorePath, keyStoreType, password, alias);
		
		String plainText = "Hello World";
		String algorithm = "SHA1withDSA";
		
		//generate the digital signature
		System.out.println("Generating digital signature");
		String encodedCipherText = ds.generateDigitalSignature(plainText, algorithm, privateKey);
		
		String publicKeyPath = "D:/Work/KeyStore/demoPublicKey.cer";
		//retrieve public key
		System.out.println("Fecthing public key");
		PublicKey publicKey = ds.getPublicKey(publicKeyPath);
		
		//verify the digital signature
		System.out.println("Verifying digital signature");
		Boolean isValid = ds.verifyDigitalSignature(plainText, encodedCipherText, algorithm, publicKey);
		
		System.out.println("Valid Digital Signature? "+isValid);
	}
}
