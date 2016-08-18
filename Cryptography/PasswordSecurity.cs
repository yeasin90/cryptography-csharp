using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
{
    public class PasswordSecurity
    {
        // Encrypting password
        // - Encryption is a two way process, we can encrypt a message with a Key and decrypt that with the same Key. This is called Symmetric Encryption
        // - So, we can consider that encryption is safe as DB will store encryted passwords.
        // - BUT no. We also have to store encryption Keys and that thing is vulnerable
        // - Another solution is using Public key and Private key with Password. This is called Asymetric Encryption. But saving those key is an overhead
        // So, optimal solution can be using Hash value

        // Using hash to store password
        // - This will be one way, cus once you hashed a password - you cannot get back that password
        // - Also, impossible/harder to get back to password from hash
        // - Attacker still may try with Brute force - mean try random password to get a matched hash value
        // - Another, RainBow table - a table with pre-calculated hash values for random password

        // Using salted hashes to Store Password
        
        public static byte[] GenerateSalt()
        {
            const int saltLength = 32; // 32byte or 256bit

            using (var randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[saltLength];
                randomNumberGenerator.GetBytes(randomNumber);

                return randomNumber;
            }
        }

        private static byte[] Combine(byte[] first, byte[] second)
        {
            var ret = new byte[first.Length + second.Length];

            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);

            return ret;
        }

        public static byte[] HashPasswordWithSalt(byte[] toBeHashed, byte[] salt)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Combine(toBeHashed, salt));
            }
        }

        // Password Based Key Derivation Function
        // - PBKDF2
        // - It's part of the RSA Public key cryptographic standards (PKCS #5 Version 2.0)
        // - 
        public static byte[] HashPassword(byte[] password, byte[] salt, int rounds)
        {
            // here round means number of iteration by Rfc2898DeriveBytes
            // this is based on moores Law, which makes the password more stronger
            using (var rfc2898 = new Rfc2898DeriveBytes(password, salt, rounds))
            {
                return rfc2898.GetBytes(32); // returns a 32byte hash
            }
        }
    }
}
