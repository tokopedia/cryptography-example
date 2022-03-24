using System;
using System.IO;
using System.Security.Cryptography;
using System.Text; 


namespace Encryption
{
    class Program
    {
         //Example public & private key
        public static string publickey  = "-----BEGIN PUBLIC KEY-----MII.....-----END PUBLIC KEY-----";
 	    public static string privateKey = "-----BEGIN RSA PRIVATE KEY-----MII.....-----END RSA PRIVATE KEY-----"; 
		

        public static void Main(string[] args)
        {
          
            string plaintext = "Hello World";
            string key = "abcd123456789";
            string encryptedPayload = "";
            string decryptedPayload = "";

            EncryptionDecryptionProcess(plaintext, key, out encryptedPayload, out decryptedPayload);

            Console.WriteLine("Plaintext    " + plaintext);
            Console.WriteLine("Encrypt Text " + encryptedPayload);
            Console.WriteLine("Decrypt Text " + decryptedPayload);

            Console.ReadKey();
        }

        
        public static void EncryptionDecryptionProcess(string payload, string key, out string encryptedPayload, out string decryptedPayload){
          
          byte[] byteskey = Encoding.ASCII.GetBytes(key);
          byte[] bytesPublicKey = Encoding.ASCII.GetBytes(publickey);
          
          //encrypt payload
          encryptedPayload =  Encrypt_Payload(payload, key);          
          //encrypt key
          byte[] encryptedKey = Encrypt_Key(byteskey, bytesPublicKey);
          
          //decrypt key
          string decryptedKey = decrypt_key(Convert.ToBase64String(encryptedKey),privateKey);
          //decrypt key
          decryptedPayload = decrypt_payload(encryptedPayload, decryptedKey);
          
      }

        // this encryption using AESGCM algoryhtm 
        //this method will encrypt param payload with the key 
        public static string Encrypt_Payload(string payload, string key)
        {
            var keyBytes = Encoding.ASCII.GetBytes(key);
            var dataToEncrypt = Encoding.Unicode.GetBytes(payload);

            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[dataToEncrypt.Length];

            //generate random nonce
			using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(nonce);
			
            using (AesGcm aesGcm = new AesGcm(keyBytes))
            {
                aesGcm.Encrypt(nonce, dataToEncrypt, ciphertext, tag, null);
            }
            //combine the encrypted text and the result will be (chiphertext + tag + nonce)
			byte[] bytes = ciphertext.Concat(tag.Concat(nonce).ToArray()).ToArray();
			return Encoding.Unicode.GetString(bytes);
		}

        //this encryption using RSA 2048 encryption OAEP SHA-256 algoryhtm
        public static byte[] Encrypt_Key(byte[] key, byte[] bytesPublicKey)
        {	 
			string publicKeyLoad = System.Text.Encoding.UTF8.GetString(bytesPublicKey);
	
			RSA rsaAlg = RSA.Create();
			rsaAlg.ImportFromPem(publicKeyLoad);
			var encryptedData = rsaAlg.Encrypt(key, RSAEncryptionPadding.OaepSHA256);
			return encryptedData; 
		}

        //this decryption using AESGCM algoryhtm 
        public static string decrypt_payload(string payload, string key){
            byte[] keyBytes   = Encoding.ASCII.GetBytes(key);
            byte[] cipherText = Encoding.UTF8.GetBytes(payload);
            
            int tagSize = 16;
            int nonceSize = 12;
            int chiperLength  = cipherText.Length - nonceSize - tagSize;
			
			byte[] nonces 	= cipherText.Skip(chiperLength + tagSize).Take(nonceSize).ToArray();
			byte[] tags 	= cipherText.Skip(chiperLength).Take(tagSize).ToArray();
            byte[] decryptedData = new byte[chiperLength];
			byte[] chiper 	= cipherText.Take(chiperLength).ToArray();
			
            using (AesGcm aesGcm = new AesGcm(keyBytes))
            {
                aesGcm.Decrypt(nonces, chiper, tags, decryptedData);
            }

            return Encoding.UTF8.GetString(decryptedData);
      }

      //this decryption using RSA 2048 OAEP SHA-256 algoryhtm
      public static string decrypt_key(string key, string privateKey){
        string rsaPrivateKeyHeaderPem = "-----BEGIN RSA PRIVATE KEY-----\n";
		string rsaPrivateKeyFooterPem = "-----END RSA PRIVATE KEY-----";
		
        byte[] ciphertextReceived = Convert.FromBase64String(key); 
		
        string rsaPrivateKeyDataPem = privateKey.Replace(rsaPrivateKeyHeaderPem, "").Replace(rsaPrivateKeyFooterPem, "").Replace("\n", "");
        var privateKeyBytes = Convert.FromBase64String(rsaPrivateKeyDataPem);
		
        using var rsa = RSA.Create();
		rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
		byte[] decryptedData = rsa.Decrypt(ciphertextReceived, RSAEncryptionPadding.OaepSHA256);

		return Encoding.UTF8.GetString(decryptedData, 0, decryptedData.Length); 
      }
    }
}