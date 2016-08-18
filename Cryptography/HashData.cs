using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
{
    public class HashData
    {
        // Hashing function takes an Input-> Passes it to a Hashing Function-> and Convert it to a Fixed size hash value
        // Hashing is one way, means you cannot get the original message from a Hash value
        // It is infeasibl to modify a message without changing the hash. Means, if you change a single character of the original message - whole hash value will be changed
        // It is infeasible to fine two different messages with the same hash

        // Hashing Algorithm in .NET
        // - MD5
        // - SHA1
        // - SHA256
        // - SHA512

        // Hashing is one way - means you cannot get the original message from a Hash value
        // Encryption is Two way operation. Means, ones you have encryption with a key - you can decrypt using that key

        // MD5
        // - Produces a 128but (16byte) hash value - typically a 32digint hex number or a base64 encoded string
        // - But a flaw was found in 1996 which is collision with other MD5 hash values. So, recomendation was to move over to the SHA (Secure Hash Family)
        // - Further collision was found in 2004 - means same hash value for two differetn message
        // - Still neede when integrating with legacy systems

        // SHA (Secure Hash Family)
        // - SHA1 - 160bit hash function. Cryptographic flaw was found in SHA1 and no longer used after 2010
        // - SHA2 - uses 32bit words
        // - SHA3 - (no support in the .net Framework directly, but has 3d party support)

        public static byte[] ComputeHashSha1(byte[] toBeHashed)
        {
            using (var sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeHashSha256(byte[] toBeHashed)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeHashSha512(byte[] toBeHashed)
        {
            using (var sha512 = SHA512.Create())
            {
                return sha512.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeHashMd5(byte[] toBeHashed)
        {
            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(toBeHashed);
            }
        }
    }
}
