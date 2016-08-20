using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
{
    public class HybridEncryptionTheory
    {
        // There are two people : Alice and Bob
        // Alice wants to send a message to Bob using Hybrid Encryption
        // 1. Alice generates an AES - 256bits of 32byte session key
        // 2. Alice generates a 128bits of 16bytes initialization vector - IV. 
        // This vector is a block of random data which is passed to AES algorithm to add addition entropy to process
        // 3. Alice then encrypts message with AES keys and IV 
        // 4. Alice then encrypts session key with Bob's public key
        // 5. Alice then calculates the HMAC of encrypted data using AES session key
        // This means that recepient can only re-calculate the Hash once they have decrypted the AES session key with there private key
        // 5. Alice sends bob : Encrypted Data, encrypted session key, IV and HMAC
        // Alice saves them before sending to Bob


        // 1. Bob first Decrypt AES session key using privte key
        // 2. Then re-calculates HMAC for encrypte data using decrypted AES session key
        // 3. Bob then campares his HAMC with the message HMAC
        // 5. If they match, then original message is intact
        // 6. If did not matched, then message should be discarded
        // 7. Bob then decrypts message using decrypted key and IV (if HMAC matches)
        // 8. Bob can now read the decrypted message

    }

    public class EncryptedPacket
    {
        public byte[] EncryptedSessionKey;
        public byte[] EncryptedData;
        public byte[] Iv;
    }

    

    

    public class HybridEncryption
    {
        private readonly AESEncryption _aes = new AESEncryption();

        public EncryptedPacket EncryptData(byte[] original, RSAWithRSAParameterKey rsaParams)
        {
            // Generate our session key.
            var sessionKey = _aes.GenerateRandomNumber(32);

            // Create the encrypted packet and generate the IV
            var encryptedPacket = new EncryptedPacket { Iv = _aes.GenerateRandomNumber(16) };

            // Encrypt our data with AES
            encryptedPacket.EncryptedData = _aes.Encrypt(original, sessionKey, encryptedPacket.Iv);

            // Encrypt the session key with RSA
            encryptedPacket.EncryptedSessionKey = rsaParams.EncryptData(sessionKey);

            return encryptedPacket;
        }

        public byte[] DecryptData(EncryptedPacket encryptedpacket, RSAWithRSAParameterKey rsaParams)
        {
            // Decrypt AES Key with RSA
            var decryptedSessionKey = rsaParams.DecryptData(encryptedpacket.EncryptedSessionKey);

            // Decrypt our data with AES using the decrypted session key
            var decryptedData = _aes.Decrypt(encryptedpacket.EncryptedData,
                                             decryptedSessionKey, encryptedpacket.Iv);

            return decryptedData;
        }
    }
}
