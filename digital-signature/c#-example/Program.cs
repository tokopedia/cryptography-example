using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;


namespace c__example
{
    class Program
    {
        static void Main(string[] args)
        {
            var publicKey = LoadPublicKey(@"../key/pub.pem");
            var privateKey = LoadPrivateKey(@"../key/priv.pem");

            byte[] msg = Encoding.ASCII.GetBytes("test");
            byte[] sig256 = privateKey.SignData(msg, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var sig64256 = Convert.ToBase64String(sig256);

            Console.WriteLine("message " + msg);
            Console.WriteLine("signature " + sig64256);

            var verify256 = publicKey.VerifyData(msg, CryptoConfig.MapNameToOID("SHA256"), sig256);

            Console.WriteLine("Signature verify 256: " + verify256);
            Console.ReadKey();
        }

        public static RSACryptoServiceProvider LoadPublicKey(String path)
        {
            System.IO.StreamReader fileStream = File.OpenText(path);
            PemReader pemReader = new PemReader(fileStream);
            AsymmetricKeyParameter KeyParameter = (AsymmetricKeyParameter)pemReader.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)KeyParameter);
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;

        }

        public static RSACryptoServiceProvider LoadPrivateKey(String path)
        {
            System.IO.StreamReader fileStream = File.OpenText(path);
            PemReader pemReader = new PemReader(fileStream);
            AsymmetricCipherKeyPair KeyParameter = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyParameter.Private);
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }
    }
}
