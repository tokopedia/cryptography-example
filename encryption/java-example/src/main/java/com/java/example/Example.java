package com.java.example;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
		String key = "tokopedia12345";

		//Encrypt Payload
		System.out.println("ENCRYPT PAYLOAD");
		String encryptedPayload = encryptPayload(payload,key);
		System.out.println(encryptedPayload);

		//Encrypt Key
		System.out.println("ENCRYPTED KEY");
		String encryptedKey= Base64.getEncoder().encodeToString(doEncryptKey(key.getBytes(),getPublicKey().getBytes()));
		System.out.println(encryptedKey);

		//Decrypt Key
		System.out.println("DECRYPT KEY");
		String decryptedKey = doDecryptKey(encryptedKey,getPrivateKey().getBytes());
		System.out.println(decryptedKey);

		//Decrypt Payload
		System.out.println("DECRYPT Payload");
		System.out.println(decyprtPayload(encryptedPayload,key));

	}



	public static byte[] doEncryptKey(byte[] key, byte[] publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
		String publicKeyOnly = new String(publicKey)
				.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\\s+","");

		byte[] encoded = Base64.getDecoder().decode(publicKeyOnly);

		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pubKey = keyFactory.generatePublic(keySpec);

		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
		cipher.init(Cipher.ENCRYPT_MODE, pubKey, oaepParameterSpec);
		byte[] encryptedKey = cipher.doFinal(key);

		return encryptedKey;
	}

	public static String doDecryptKey(String key,byte[] bytesPrivateKey) throws GeneralSecurityException, IOException {
		java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		String stringPrivateKey = new String(bytesPrivateKey)
				.replace("-----BEGIN RSA PRIVATE KEY-----", "")
				.replace("-----END RSA PRIVATE KEY-----", "")
				.replaceAll("\\s+","");

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(stringPrivateKey));
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


	public static String getPublicKey (){
		String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArWEvqTWJO6+N+My/UH/b\n" +
				"662cKvUVEIxovne8sSM/pgPUAPdO/4IUHtvQp2W+kyrpKMdk0W63Icnhg739IgRH\n" +
				"jBnKUH9Yc/muAIMWT0CDHCEFbvvc71HmKVN9dOreHAVsFx4+R07x+z2fYc/oiZ/x\n" +
				"CWxCvQdTmeJx1vdFe0nUA5VZTC7My7+A8lJ/EayhDny8IVmS40nzUzBMK5UsQlDZ\n" +
				"h+AS1jotCTmEAjdIuX/fi4cWBfCohW8qFsQKF8iN2hcD1HShXdFiVx4GHAFzMy0r\n" +
				"wSJ86wA9RskHYESInYOj93B3IWFaDcAUd3RH/eNvfHsBCkvFUfj9k5lAYx8+pnY1\n" +
				"lQIDAQAB\n" +
				"-----END PUBLIC KEY-----";
		return publicKey;
	}

	public static String getPrivateKey(){
		String privateKey = "-----BEGIN RSA PRIVATE KEY-----" +
				"MIIEowIBAAKCAQEArWEvqTWJO6+N+My/UH/b662cKvUVEIxovne8sSM/pgPUAPdO" +
				"/4IUHtvQp2W+kyrpKMdk0W63Icnhg739IgRHjBnKUH9Yc/muAIMWT0CDHCEFbvvc" +
				"71HmKVN9dOreHAVsFx4+R07x+z2fYc/oiZ/xCWxCvQdTmeJx1vdFe0nUA5VZTC7M" +
				"y7+A8lJ/EayhDny8IVmS40nzUzBMK5UsQlDZh+AS1jotCTmEAjdIuX/fi4cWBfCo" +
				"hW8qFsQKF8iN2hcD1HShXdFiVx4GHAFzMy0rwSJ86wA9RskHYESInYOj93B3IWFa" +
				"DcAUd3RH/eNvfHsBCkvFUfj9k5lAYx8+pnY1lQIDAQABAoIBAQCBsbF1YhbGDwyk" +
				"kISMMxjPs46ek7auKlowIGGGIFf8V+C+2EC/4Q4sB0KN9g4ZCIBhgMZp4+gZ3mpT" +
				"oks4pvreUmyEyr3gA2Wl/Gkz344z/H+UBdO/MgR55Xpzez2quGOi53yu2t8okXAo" +
				"Ot44FOy5n8JMpK5k7n85zr6q+w8dnd4945lmeDugwfdeNazuAmd12IoVhP6D9ksj" +
				"MnhU0bsM5V6NbRQrkdOikN5beG3oBmnImKNnBqeaEAv0M+r5sZCDvqr1BfrVDkpv" +
				"WmCjiw2e8FKB1QzzynBjOeN2alvm9uXxBU7D5nfBkdFptl5LV9y5O74qw/5mBm9Z" +
				"wfvf/iABAoGBAOZEBNrYlaVHFEhHcpWoEWozGzMCmvQ80KqPz7nJundeAlcRyi3Z" +
				"OkktzhYpioFVw/V1baLs38G2kWWsqha2a7aIScwshcvlOVKF3xFQEn+PUudCVLsZ" +
				"h00S890Cw9f96U/Nq/KweH9SprmzXD/u/jt2k4KGCyTDivnWhHiLtFfxAoGBAMDB" +
				"oyOxkUh9Iq7vbB3t29WluLGEXVibce8Ct+9s1ne6EqUcRbYzzxvPNQ6SLcypdSot" +
				"kysHS9J7T9qJiD7BQ6U/uPWssfA0Wi0/t7AaBQbg8b/XQHxy+7C0so6cWRnA8wi0" +
				"vGxUT/Xaj0t5RqSD2M2CNqKDD7iCfspkPhYizzvlAoGAbjrPjCg0cvt01SkGzGe5" +
				"dnpioee0YAkg5xWTHmBYmD3zptTIUWx0/4Ui6+8U89cnyMBfLKhycRxBvEeM4PSQ" +
				"2b+ifFAv+KyR5VRatcH8KP5mdHiHcU3GPHo/LWTede6CGwbdMn+SH3lkgO9A0QZK" +
				"xBJ+iPQ8L2xAgltT7RULzzECgYBgCFkJ8G6MaeO8ugXoh1euAomYz3ReL9u8k2Mm" +
				"Qtg7ABZH8mT82KUHmt05LDTrMUXxRJF8r37kF5F6NGkPsuPL0YqJw4dHQB3pS0Rt" +
				"1RjKC4oF5Oz406R3rh8Dk/uELDApFzqE0iCgQUqA9KPwVMvP317u6lMLvuACX5zb" +
				"FG6gzQKBgHBfcYUDtNYZGLknROdCORZ4v/l+VXxCfX3aigukCfq4oJH7rL+TWbkN" +
				"I3nrJjdmJwURO3NkNBhLvqWGLMzrdB5PtVBFENBwtbKhTrRsf+kYTnxDwdQDSIIF" +
				"omzigKfZ5BkDxYO4veyISNMAmUs7MbVSGO3HsovQpAxJv5ZnhnBj" +
				"-----END RSA PRIVATE KEY-----";
		return privateKey;
	}

}
