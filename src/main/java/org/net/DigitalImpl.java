package org.net;


import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class DigitalImpl {
	
	public String encrypteBase64(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}
	
	public byte[] decrypteBase64(String data) {
		return Base64.getDecoder().decode(data);
	}
	
	public SecretKey generatorSecretKey() throws Exception{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		return  keyGenerator.generateKey();
	}
	
	public byte[] encoderAES(byte[] data, SecretKey secret) throws Exception {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secret);
		return cipher.doFinal(data);
	}
	
	public byte[] decoderAES(byte[] data, SecretKey secret) throws Exception {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, secret);
		return cipher.doFinal(data);
	}
	
	public KeyPair generatorKeyRSA() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(512);
		return keyPairGenerator.generateKeyPair();
	}
	
	public byte[] encoderRSA(byte[] data,PublicKey publicKey) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(data);		
	}
	
	public byte[] decoderRSA(byte[] data,PrivateKey privateKey) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decrypt = cipher.doFinal(data);		
		return decrypt;
	}
	
	public PublicKey publicKeyCert(String fileName) throws Exception{
		FileInputStream fileInputStream = new FileInputStream(fileName);
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
		return certificate.getPublicKey();
	}
	
	public PrivateKey privateKeyJKS(String fileName, String passwordJKS, String allias) throws Exception {
		FileInputStream fileInputStream = new FileInputStream(fileName);
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(fileInputStream,passwordJKS.toCharArray());
		Key key = keyStore.getKey(allias, passwordJKS.toCharArray());
		PrivateKey myKey = (PrivateKey) key;
		
		return myKey;
	}
	
	

}
