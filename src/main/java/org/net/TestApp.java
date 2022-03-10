package org.net;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;

import javax.crypto.SecretKey;

public class TestApp {

	public static void main(String[] args) throws Exception {
		DigitalImpl digitImpl = new DigitalImpl();
		String donnee = "Ma fille se nomme Mayssane";
		byte[] data = donnee.getBytes();
		
		System.out.println("===============cryptage BASE64=============");
		String encrypted = digitImpl.encrypteBase64(data);
		System.out.println(encrypted);
		byte[] decrypted = digitImpl.decrypteBase64(encrypted);
		System.out.println(new String (decrypted));
		System.out.println("===============cryptage AES=============");
		SecretKey secret = digitImpl.generatorSecretKey();
		byte[] encryptecAES = digitImpl.encoderAES(data, secret);
		System.out.println(Arrays.toString(encryptecAES));
		byte[] decryptecAES = digitImpl.decoderAES(encryptecAES, secret);
		System.out.println(new String(decryptecAES));
		System.out.println("===============cryptage RSA=============");
		KeyPair keyPair = digitImpl.generatorKeyRSA();
		byte[] encoderRSA = digitImpl.encoderRSA(data, keyPair.getPublic());
		System.out.println(Arrays.toString(encoderRSA));
		byte[] decoderRSA= digitImpl.decoderRSA(encoderRSA, keyPair.getPrivate());
		System.out.println(new String(decoderRSA));
		
		System.out.println("===============cryptage JKS=============");
	    byte[] encoderCert = digitImpl.encoderRSA(data, digitImpl.publicKeyCert("publicKey.cert"));
		System.out.println(Arrays.toString(encoderCert));
		PrivateKey privateKeyJKS = digitImpl.privateKeyJKS("crypte.jks","123456", "kone");
		byte[] decoderJKS= digitImpl.decoderRSA(encoderCert,privateKeyJKS);
		System.out.println(new String(decoderJKS));
		

	}

}
