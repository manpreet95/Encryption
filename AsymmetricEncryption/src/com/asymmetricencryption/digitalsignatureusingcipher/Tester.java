/*
 * 1. Fetch the private key from keystore
 * 2. Generate digital signature
 * 3. Send signature and public key
 * 4. Verify the digital signature
 * 
 * */
package com.asymmetricencryption.digitalsignatureusingcipher;

import java.security.PrivateKey;
import java.security.PublicKey;

public class Tester {
	
	public static void main(String args[]) throws Exception {
				
		String keyStorePath = "D:/Work/KeyStore/keystore.jks";
		String keyStoreType = "JCEKS";
		char[] password = "123456789".toCharArray();
		String alias = "demorsa";
		
		
		DigitalSignature ds = new DigitalSignatureImpl();
		
		//get private key
		System.out.println("fecthing private key");
		PrivateKey privateKey = ds.getPrivateKey(keyStorePath, keyStoreType, password, alias);
		
		
		String plainText = "Hello Worldsbsjd";
		String algorithm = "RSA";
		
		//generate the digital signature
		System.out.println("generating digital signature");
		String encodedCipherText = ds.generateDigitalSignature(plainText, algorithm, privateKey);
		
		String publicKeyPath = "D:/Work/KeyStore/demoRSAPublicKey.cer";
		//retrieve public key
		System.out.println("fecthing public key");
		PublicKey publicKey = ds.getPublicKey(publicKeyPath);
		
		//verify the digital signature
		System.out.println("verifying digital signature");
		Boolean isValid = ds.verifyDigitalSignature(plainText, encodedCipherText, algorithm, publicKey);
		
		System.out.println("Valid digital signature? "+isValid);
	}
}
