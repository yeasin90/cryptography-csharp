using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
{
    public class RandomNumber
    {
        // Random numbers are used for generating encryption keys
        // Software based random numbers are not always random
        // Randomness can be created from human interaction

        // System.Random and it's Problem
        // - pseudo randmon number generator
        // - A seed value is passed into the constructor
        // - This seed value should be different each time
        // - System.Random is deterministic ad predictable

        // Secure Random numbers with RNGCryptoServiceProvider
        // - Random numbers used for creating encryption keys and for hashing
        // RNGCryptoServiceProvider is a more secure way to generate random numbers
        // Cons - slower to execute bt more secured :)
        // RNGCryptoServiceProvider is Thread safe
        public static byte[] GenerateRandomNumber(int length)
        {
            using (var randomNumberGeneraotr = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[length];
                randomNumberGeneraotr.GetBytes(randomNumber);

                return randomNumber;
            }
        }
    }
}
