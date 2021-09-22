package com.java.example;

import java.io.File;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class pkcs {

	public static void main(String[] args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try {
			PrivateKey privateK = getPrivateKey("../key/priv.pem");
			if (privateK == null)
				System.out.println("NULL");
			PublicKey publicK = getPublicKey("../key/pub.pem");

			String message = "test";
			String signature = Sign(privateK, message);

			System.out.println("Signed: " + signature);

			System.out.println(Verify(publicK, signature, message));
		} catch (Exception ex) {
			System.out.println(ex.toString());
		}

	}

	public static PublicKey getPublicKey(String fileName) {
		try {
			KeyFactory factory = KeyFactory.getInstance("RSA");
			File file = new File(fileName);
			try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {
				PemObject pemObject = pemReader.readPemObject();
				byte[] content = pemObject.getContent();
				X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
				PublicKey publicKey = factory.generatePublic(pubKeySpec);
				return publicKey;
			} catch (Exception exx) {
				System.out.println(exx.toString());
			}
		} catch (Exception ex) {
			System.out.println(ex.toString());
		}

		return null;
	}

	public static PrivateKey getPrivateKey(String fileName) {
		try {
			KeyFactory factory = KeyFactory.getInstance("RSA");
			File file = new File(fileName);
			try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {
				PemObject pemObject = pemReader.readPemObject();
				byte[] content = pemObject.getContent();
				PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
				PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
				return privateKey;
			} catch (Exception exx) {
				System.out.println(exx.toString());
			}
		} catch (Exception ex) {
			System.out.println(ex.toString());
		}

		return null;
	}

	public static boolean Verify(PublicKey publicKey, String signature, String msg) {
		try {
			byte[] sigBytes = Base64.getDecoder().decode(signature.getBytes());

			Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);

			byte[] decSig = cipher.doFinal(sigBytes);
			ASN1InputStream aIn = new ASN1InputStream(decSig);
			ASN1Sequence seq = (ASN1Sequence) aIn.readObject();

			MessageDigest hash = MessageDigest.getInstance("SHA-256", "BC");
			hash.update(msg.getBytes());

			ASN1OctetString sigHash = (ASN1OctetString) seq.getObjectAt(1);
			return MessageDigest.isEqual(hash.digest(), sigHash.getOctets());
		} catch (Exception ex) {

		}

		return false;
	}

	public static String Sign(PrivateKey privateKey, String msg) {
		try {
			Signature signature = Signature.getInstance("SHA256withRSA", "BC");
			signature.initSign(privateKey);

			byte[] message = msg.getBytes();
			signature.update(message);

			byte[] sigBytes = signature.sign();

			byte[] sig64 = Base64.getEncoder().encode(sigBytes);
			return new String(sig64);
		} catch (Exception ex) {
			System.out.println(ex.toString());
		}
		return "";
	}
}

