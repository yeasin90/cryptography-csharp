using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
            Console.ReadLine();
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
