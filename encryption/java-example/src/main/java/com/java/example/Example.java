package com.java.example;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

public class Example {

	public static void main(String[] args) throws Exception {
		// write your code here
		String payload = "{\"hello\": \"world\"}";

		//AES only supports key sizes of 16, 24 or 32 bytes
		String key = "tokopedia:ts-1647510734065138000";

		//Encrypt Payload
		System.out.println("ENCRYPT PAYLOAD");
		String encryptedPayload = encryptPayload(payload,key);
		System.out.println(encryptedPayload);

		//Encrypt Key
		System.out.println("ENCRYPTED KEY");
		File publicKey = new File("../key/pub.pem");
		String encryptedKey= Base64.getEncoder().encodeToString(doEncryptKey(key.getBytes(),getPublicKey(publicKey)));
		System.out.println(encryptedKey);

		//Decrypt Key
		System.out.println("DECRYPT KEY");
		File privateKey = new File("../key/priv.pem");
		String decryptedKey = doDecryptKey(encryptedKey,getPrivateKey(privateKey));
		System.out.println(decryptedKey);

		//Decrypt Payload
		System.out.println("DECRYPT Payload");
		System.out.println(decyprtPayload(encryptedPayload,key));

	}



	public static byte[] doEncryptKey(byte[] key, byte[] publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
	
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pubKey = keyFactory.generatePublic(keySpec);

		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
		cipher.init(Cipher.ENCRYPT_MODE, pubKey, oaepParameterSpec);
		byte[] encryptedKey = cipher.doFinal(key);

		return encryptedKey;
	}

	public static String doDecryptKey(String key,byte[] privateKey) throws GeneralSecurityException, IOException {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privKey = kf.generatePrivate(keySpec);

		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
		cipher.init(Cipher.DECRYPT_MODE, privKey,oaepParameterSpec);

		byte[] keyDecoded = Base64.getDecoder().decode(key.getBytes());
		byte[] result = cipher.doFinal(keyDecoded);
		return new String(result);
	}


	public static String decyprtPayload(String payload, String key) throws GeneralSecurityException {

		byte[] payloadByte = Base64.getDecoder().decode(payload);
		byte[] nonce = Arrays.copyOfRange(payloadByte, payloadByte.length-12, payloadByte.length);
		byte[] decode = Arrays.copyOfRange(payloadByte, 0, payloadByte.length-12);

		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
		GCMParameterSpec params = new GCMParameterSpec(128, nonce);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, params);

		byte[] plaintext = cipher.doFinal(decode);

		return new String(plaintext);
	}


	public static String encryptPayload(String payload, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {

		byte[] nonce = new byte[12];
		new SecureRandom().nextBytes(nonce);

		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
		GCMParameterSpec params = new GCMParameterSpec(128, nonce);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);
		byte[] encryptedText = cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8));
		ByteBuffer byteBuffer = ByteBuffer.allocate(nonce.length + encryptedText.length);
		byteBuffer.put(encryptedText);
		byteBuffer.put(nonce);

		return Base64.getEncoder().encodeToString(byteBuffer.array());
	}


	public static byte[] getPublicKey (File file) throws Exception{
		String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());
		String publicKeyOnly = new String(key)
		.replace("-----BEGIN PUBLIC KEY-----", "")
		.replace("-----END PUBLIC KEY-----", "")
		.replaceAll("\\s+","");

		byte[] encoded = Base64.getDecoder().decode(publicKeyOnly);
		return encoded;
	}

	public static byte[] getPrivateKey(File file) throws Exception{
		String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());
		String stringPrivateKey = new String(key)
				.replace("-----BEGIN RSA PRIVATE KEY-----", "")
				.replace("-----END RSA PRIVATE KEY-----", "")
				.replaceAll("\\s+","");

		byte[] encoded = Base64.getDecoder().decode(stringPrivateKey);
		return encoded;
	}

}
