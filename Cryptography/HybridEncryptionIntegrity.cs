using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
{
    public class EncryptedPacketIntegrityCheck
    {
        public byte[] EncryptedSessionKey;
        public byte[] EncryptedData;
        public byte[] Iv;
        public byte[] Hmac;
    }

    public class HybridEncryptionIntegirtyCheck
    {
        private readonly AESEncryption _aes = new AESEncryption();

        public EncryptedPacketIntegrityCheck EncryptData(byte[] original, RSAWithRSAParameterKey rsaParams)
        {
            // Generate our session key.
            var sessionKey = _aes.GenerateRandomNumber(32);

            // Create the encrypted packet and generate the IV
            var encryptedPacket = new EncryptedPacketIntegrityCheck { Iv = _aes.GenerateRandomNumber(16) };

            // Encrypt our data with AES
            encryptedPacket.EncryptedData = _aes.Encrypt(original, sessionKey, encryptedPacket.Iv);

            // Encrypt the session key with RSA
            encryptedPacket.EncryptedSessionKey = rsaParams.EncryptData(sessionKey);

            using (var hmac = new HMACSHA256(sessionKey))
            {
                encryptedPacket.Hmac = hmac.ComputeHash(encryptedPacket.EncryptedData);
            }

            return encryptedPacket;
        }

        public byte[] DecryptData(EncryptedPacketIntegrityCheck encryptedpacket, RSAWithRSAParameterKey rsaParams)
        {
            // Decrypt AES Key with RSA
            var decryptedSessionKey = rsaParams.DecryptData(encryptedpacket.EncryptedSessionKey);

            using (var hmac = new HMACSHA256(decryptedSessionKey))
            {
                var hmacToCheck = hmac.ComputeHash(encryptedpacket.EncryptedData);

                if (!Comparer(encryptedpacket.Hmac, hmacToCheck))
                {
                    throw new CryptographicException("HMAC for decryption does not match");
                }
            }

            // Decrypt our data with AES using the decrypted session key
            var decryptedData = _aes.Decrypt(encryptedpacket.EncryptedData,
                                             decryptedSessionKey, encryptedpacket.Iv);

            return decryptedData;
        }

        private bool Comparer(byte[] array1, byte[] array2)
        {
            var result = array1.Length == array2.Length;

            for (var i = 0; i < array1.Length && i < array2.Length; ++i)
            {
                result &= array1[i] == array2[i];
            }

            return result;
        }
    }
}
