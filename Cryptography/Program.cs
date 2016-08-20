using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
{
    class Program
    {
        static void Main(string[] args)
        {
            //RandomNumberGenerator();
            //HashAlgorithms();
            //Hmac();
            //PasswordWithSalt();
            //PasswordWithPBKDF();
            //EncryptDecryptWithDES();
            //EncryptDecryptWithTripleDES();
            //EncryptDecryptWithRSAWithRSAParameterKey();
            //EncryptDecryptWithRSAWithXML();
            //EncryptDecryptWithRSAWithCSPKey();
            //HyrbidEncrypDecrypt();
            //HybridIntergityCheckEncrypDecrypt();
            //DigitalSignatureExample();
            Console.ReadLine();
        }

        public static void DigitalSignatureExample()
        {
            var document = Encoding.UTF8.GetBytes("Document to Sign");
            byte[] hashedDocument;

            using (var sha256 = SHA256.Create())
            {
                hashedDocument = sha256.ComputeHash(document);
            }

            var digitalSignature = new DigitalSignatureImp();
            digitalSignature.AssignNewKey();

            var signature = digitalSignature.SignData(hashedDocument);
            var verified = digitalSignature.VerifySignature(hashedDocument, signature);

            Console.WriteLine("Digital Signature Demonstration in .NET");
            Console.WriteLine("---------------------------------------");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Original Text = " + 
                Encoding.Default.GetString(document));

            Console.WriteLine();
            Console.WriteLine("Digital Signature = " + 
                Convert.ToBase64String(signature));

            Console.WriteLine();
            Console.WriteLine(verified
                ? "The digital signature has been correctly verified"
                : "The digital signature has NOT been correctly verified");
        }

        public static void HybridIntergityCheckEncrypDecrypt()
        {
            const string original = "Very secret and important information that can not into the hacker.";

            var hybrid = new HybridEncryptionIntegirtyCheck();

            var rsaParams = new RSAWithRSAParameterKey();
            rsaParams.AssignNewKey();

            Console.WriteLine("Hybrid Encryption with Integrity Check Demonstration in .NET");
            Console.WriteLine("------------------------------------------------------------");
            Console.WriteLine();

            try
            {
                var encryptedBlock = hybrid.EncryptData(Encoding.UTF8.GetBytes(original), rsaParams);
                var decrypted = hybrid.DecryptData(encryptedBlock, rsaParams);

                Console.WriteLine("Original Message = " + original);
                Console.WriteLine();
                Console.WriteLine("Message After Decryption = " + Encoding.UTF8.GetString(decrypted));
            }
            catch(CryptographicException ex)
            {
                Console.WriteLine("Error : " + ex.Message);
            }
        }

        public static void HyrbidEncrypDecrypt()
        {
            const string original = "Very secret and important information that can not into the hacker.";

            var rsaParams = new RSAWithRSAParameterKey();
            rsaParams.AssignNewKey();

            var hybrid = new HybridEncryption();

            var encryptedBlock = hybrid.EncryptData(Encoding.UTF8.GetBytes(original), rsaParams);
            var decrypted = hybrid.DecryptData(encryptedBlock, rsaParams);

            Console.WriteLine("Hybrid Encryption Demonstration in .NET");
            Console.WriteLine("---------------------------------------");
            Console.WriteLine();
            Console.WriteLine("Original Message = " + original);
            Console.WriteLine();
            Console.WriteLine("Message After Decruption = " + Encoding.UTF8.GetString(decrypted));
        }

        public static void EncryptDecryptWithRSAWithCSPKey()
        {
            var rsaCsp = new RSAWithCSPKey();
            const string original = "Text to encrypt";

            rsaCsp.AssignNewKey();

            var encryptedCsp = rsaCsp.EncryptData(Encoding.UTF8.GetBytes(original));
            var decryptedCsp = rsaCsp.DecryptData(encryptedCsp);

            rsaCsp.DeleteKeyInCsp();

            Console.WriteLine("CSP Based Key");
            Console.WriteLine("------------------------------------");
            Console.WriteLine();
            Console.WriteLine("Original Text = " + original);
            Console.WriteLine();
            Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encryptedCsp));
            Console.WriteLine();
            Console.WriteLine("Decrypted Text = " + Encoding.Default.GetString(decryptedCsp));
            Console.WriteLine();
            Console.WriteLine();
        }

        public static void EncryptDecryptWithRSAWithXML()
        {
            var rsa = new RSAWithXMLKey();
            const string original = "Text to encrypt";
            const string publicKeyPath = "c:\\temp\\publickey.xml";
            const string privateKeyPath = "c:\\temp\\privatekey.xml";

            rsa.AssignNewKey(publicKeyPath, privateKeyPath);

            var encrypted = rsa.EncryptData(publicKeyPath,Encoding.UTF8.GetBytes(original));
            var decrypt = rsa.DecryptData(privateKeyPath, encrypted);

            Console.WriteLine("Xml Based Key");
            Console.WriteLine("------------------------------------");
            Console.WriteLine();
            Console.WriteLine("Original Text = " + original);
            Console.WriteLine();
            Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encrypted));
            Console.WriteLine();
            Console.WriteLine("Decrypted Text = " + Encoding.Default.GetString(decrypt));
            Console.WriteLine();
            Console.WriteLine();
        }

        public static void EncryptDecryptWithRSAWithRSAParameterKey()
        {
            var rsaParams = new RSAWithRSAParameterKey();
            const string original = "Text to encrypt";

            rsaParams.AssignNewKey();

            var encryptedRsaParams = rsaParams.EncryptData(Encoding.UTF8.GetBytes(original));
            var decryptedRsaParams = rsaParams.DecryptData(encryptedRsaParams);

            Console.WriteLine("RSA Encryption Demonstration in .NET");
            Console.WriteLine("------------------------------------");
            Console.WriteLine();
            Console.WriteLine("In Memory Key");
            Console.WriteLine();
            Console.WriteLine("Original Text = " + original);
            Console.WriteLine();
            Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encryptedRsaParams));
            Console.WriteLine();
            Console.WriteLine("Decrypted Text = " + Encoding.Default.GetString(decryptedRsaParams));
            Console.WriteLine();
            Console.WriteLine();
        }

        public static void EncryptDecryptWithAES()
        {
            var des = new AESEncryption();
            var key = des.GenerateRandomNumber(32);
            var iv = des.GenerateRandomNumber(16);
            const string original = "Text to encrypt";

            var encrypted = des.Encrypt(Encoding.UTF8.GetBytes(original), key, iv);
            var decrypted = des.Decrypt(encrypted, key, iv);

            var decryptedMessage = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine("AES Encryption Demonstration in .NET");
            Console.WriteLine("------------------------------------");
            Console.WriteLine();
            Console.WriteLine("Original Text = " + original);
            Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Decrypted Text = " + decryptedMessage);
        }

        public static void EncryptDecryptWithTripleDES()
        {
            var des = new TripleDesEncryption();
            var key = des.GenerateRandomNumber(24);
            var iv = des.GenerateRandomNumber(8);
            const string original = "Text to encrypt";

            var encrypted = des.Encrypt(Encoding.UTF8.GetBytes(original), key, iv);
            var decrypted = des.Decrypt(encrypted, key, iv);

            var decryptedMessage = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine("Triple DES Encryption Demonstration in .NET");
            Console.WriteLine("------------------------------------");
            Console.WriteLine();
            Console.WriteLine("Original Text = " + original);
            Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Decrypted Text = " + decryptedMessage);
        }

        public static void EncryptDecryptWithDES()
        {
            var des = new DesEncryption();
            var key = des.GenerateRandomNumber(8);
            var iv = des.GenerateRandomNumber(8);
            const string original = "Text to encrypt";

            var encrypted = des.Encrypt(Encoding.UTF8.GetBytes(original), key, iv);
            var decrypted = des.Decrypt(encrypted, key, iv);

            var decryptedMessage = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine("DES Encryption Demonstration in .NET");
            Console.WriteLine("------------------------------------");
            Console.WriteLine();
            Console.WriteLine("Original Text = " + original);
            Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encrypted));
            Console.WriteLine("Decrypted Text = " + decryptedMessage);
        }

        public static void PasswordWithPBKDF()
        {
            const string passwordToHash = "VeryComplexPassword";

            Console.WriteLine("Password Based Key Derication Function Demonstration in .NET");
            Console.WriteLine("............................................................");
            Console.WriteLine();
            Console.WriteLine("PBKDF2 Hashes");
            Console.WriteLine();

            // Increases by Moores Law
            HashPassword(passwordToHash, 100);
            HashPassword(passwordToHash, 1000);
            HashPassword(passwordToHash, 1000);
            HashPassword(passwordToHash, 5000);
        }

        private static void HashPassword(string passwordToHash, int numberOfRounds)
        {
            var sw = new Stopwatch();

            sw.Start();

            var hashedPassword = PasswordSecurity.HashPassword(Encoding.UTF8.GetBytes(passwordToHash),
                PasswordSecurity.GenerateSalt(),
                numberOfRounds);

            sw.Stop();

            Console.WriteLine();
            Console.WriteLine("Password to hash : " + passwordToHash);
            Console.WriteLine("Hashed Password : " + Convert.ToBase64String(hashedPassword));
            Console.WriteLine("Iteration <" + numberOfRounds + "> Elapsed Time : " + sw.ElapsedMilliseconds);
        }

        public static void PasswordWithSalt()
        {
            const string password = "V3ryC0mpl3xP455w0rd";
            byte[] salt = PasswordSecurity.GenerateSalt();

            Console.WriteLine("Hash Password with Salt Demonstration in .NET");
            Console.WriteLine("..............................................");
            Console.WriteLine();
            Console.WriteLine("Password : " + password);
            Console.WriteLine("Salt = " + Convert.ToBase64String(salt));
            Console.WriteLine();

            var hashedPassword1 = PasswordSecurity.HashPasswordWithSalt(
                Encoding.UTF8.GetBytes(password),
                salt);

            Console.WriteLine();
            Console.WriteLine("Hashed Password = " + Convert.ToBase64String(hashedPassword1));
            Console.WriteLine();
        }

        public static void Hmac()
        {
            const string originalMessage = "Original Message to hash";
            const string originalMessage1 = "This is another message to hash"; 
            // if we change this value to originalMessage, then same HMAC will be generated
            // This proves that, for same message we will have same hash when we use the same cryptographic key

            Console.WriteLine("HMAC Demonstration in .NET");
            Console.WriteLine("...........................");
            Console.WriteLine();

            var key = HMAC.GenerateKey();

            var md5HashedMessage = HMAC.ComputeHmacmd5(Encoding.UTF8.GetBytes(originalMessage), key);
            var md5HashedMessage2 = HMAC.ComputeHmacmd5(Encoding.UTF8.GetBytes(originalMessage1), key);

            var sha1HashedMessage = HMAC.ComputeHmacsha1(Encoding.UTF8.GetBytes(originalMessage), key);
            var sha1HashedMessage2 = HMAC.ComputeHmacsha1(Encoding.UTF8.GetBytes(originalMessage1), key);

            var sha256HashedMessage = HMAC.ComputeHmacsha256(Encoding.UTF8.GetBytes(originalMessage), key);
            var sha256HashedMessage2 = HMAC.ComputeHmacsha256(Encoding.UTF8.GetBytes(originalMessage1), key);

            var sha512HashedMessage = HMAC.ComputeHmacsha512(Encoding.UTF8.GetBytes(originalMessage), key);
            var sha512HashedMessage2 = HMAC.ComputeHmacsha512(Encoding.UTF8.GetBytes(originalMessage1), key);

            Console.WriteLine();
            Console.WriteLine("MD5 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(md5HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(md5HashedMessage2));

            Console.WriteLine();
            Console.WriteLine("SHA1 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(sha1HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(sha1HashedMessage2));

            Console.WriteLine();
            Console.WriteLine("SHA2 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(sha256HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(sha256HashedMessage2));

            Console.WriteLine();
            Console.WriteLine("SHA 512 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(sha512HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(sha512HashedMessage2));
        }

        public static void HashAlgorithms()
        {
            const string originalMessage = "Original Message to hash";
            const string originalMessage1 = "This is another message to hash";

            Console.WriteLine("Secure hashData Deibstration in .NET");
            Console.WriteLine("....................................");
            Console.WriteLine();
            Console.WriteLine("Original Message 1 : " + originalMessage);
            Console.WriteLine("Original Message 2 : " + originalMessage1);

            var md5HashedMessage = HashData.ComputeHashMd5(Encoding.UTF8.GetBytes(originalMessage));
            var md5HashedMessage2 = HashData.ComputeHashMd5(Encoding.UTF8.GetBytes(originalMessage1));

            var sha1HashedMessage = HashData.ComputeHashSha1(Encoding.UTF8.GetBytes(originalMessage));
            var sha1HashedMessage2 = HashData.ComputeHashSha1(Encoding.UTF8.GetBytes(originalMessage1));

            var sha256HashedMessage = HashData.ComputeHashSha256(Encoding.UTF8.GetBytes(originalMessage));
            var sha256HashedMessage2 = HashData.ComputeHashSha256(Encoding.UTF8.GetBytes(originalMessage1));

            var sha512HashedMessage = HashData.ComputeHashSha512(Encoding.UTF8.GetBytes(originalMessage));
            var sha512HashedMessage2 = HashData.ComputeHashSha512(Encoding.UTF8.GetBytes(originalMessage1));

            Console.WriteLine();
            Console.WriteLine("MD5 Hashes");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(md5HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(md5HashedMessage2));

            Console.WriteLine();
            Console.WriteLine("SHA1 Hashes");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(sha1HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(sha1HashedMessage2));

            Console.WriteLine();
            Console.WriteLine("SHA2 Hashes");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(sha256HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(sha256HashedMessage2));

            Console.WriteLine();
            Console.WriteLine("SHA 512 Hashes");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(sha512HashedMessage));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(sha512HashedMessage2));
        }

        public static void RandomNumberGenerator()
        {
            Console.WriteLine("Random number Demonstration in .NET");
            Console.WriteLine("...................................");
            Console.WriteLine();

            for (int i = 0; i < 10; i++)
            {
                Console.WriteLine("Random Number " + i + " : "
                    + Convert.ToBase64String(RandomNumber.GenerateRandomNumber(32)));
            }
        }
    }
}
