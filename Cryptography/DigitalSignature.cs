using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
{
    public class DigitalSignature
    {
        // Based on Asymmetric Cryptography
        // 1. Alice sends a message to Bob and that message will be signed with a digital signature
        // 2. So, Alice encrypts her data that she wants to send to Bob (does not matter with Symmetric or Asymmetric algorithm)
        // 3. After encryption, Alice takes the Hash of that data
        // 4. Next, Alice signs the data with her private key
        // 5. Next, Alice sends - Encrypted Data, hash and signature to Bob
        // 6. Bob re-calculates the hash of the encrypted data
        // 7. Bob verifies the digital signature using the calculated hash and the senders public key
        // 8. This will tell Bob if the signature is valid or NOT
        // 9. If it is valid, Bob can be confident that it was Alice that sends him the message, as it can only be signed using her private key - which only Alice knows
        // 10. If it is not VALID, then it can be discarded

        // In RSA, we encrypt data with recepient Public Key. 
        // Then Recepient decrypt with their Private key.
        // When Sender signs a message, they use their own private key
        // Then recepeint verifies the signature using senders Public key
        // It's due to the fact that, the recepient can trust that the message was sent by that sender, as only they would know their private key
    }

    public class DigitalSignatureImp
    {
        private RSAParameters _publicKey;
        private RSAParameters _privateKey;

        public void AssignNewKey()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                _publicKey = rsa.ExportParameters(false);
                _privateKey = rsa.ExportParameters(true);
            }
        }

        public byte[] SignData(byte[] hashOfDataToSign)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(_privateKey);

                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
                rsaFormatter.SetHashAlgorithm("SHA256");

                return rsaFormatter.CreateSignature(hashOfDataToSign);
            }
        }

        public bool VerifySignature(byte[] hashOfDataToSign, byte[] signature)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(_publicKey);

                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm("SHA256");

                return rsaDeformatter.VerifySignature(hashOfDataToSign, signature);
            }
        }
    }
}
