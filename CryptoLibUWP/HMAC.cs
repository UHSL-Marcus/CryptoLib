using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace CryptoLibUWP
{
    public class HMAC
    {
        public enum HmacAlgorithms
        {
            SHA1,
            SHA256,
            SHA384,
            SHA512
        }
        public static string Hash(string input, string key, HmacAlgorithms algor)
        {
            IBuffer hash = null;
            CryptographicKey hmacKey; MacAlgorithmProvider HmacProv; IBuffer keyBuff; IBuffer inputBuff;
            GetHMACInfo(input, key, algor, out hmacKey, out HmacProv, out keyBuff, out inputBuff);

            hash = CryptographicEngine.Sign(hmacKey, inputBuff);

            return CryptographicBuffer.EncodeToHexString(hash);

        }

        public static bool ValidateHash(string input, string key, string hmac, HmacAlgorithms algor)
        {
            IBuffer hmacBuff = CryptographicBuffer.DecodeFromHexString(hmac);
            CryptographicKey hmacKey; MacAlgorithmProvider HmacProv; IBuffer keyBuff; IBuffer inputBuff;
            GetHMACInfo(input, key, algor, out hmacKey, out HmacProv, out keyBuff, out inputBuff);

            return CryptographicEngine.VerifySignature(hmacKey, inputBuff, hmacBuff);

            
        }

        private static void GetHMACInfo(string input, string key, HmacAlgorithms algor, out CryptographicKey hmacKey, out MacAlgorithmProvider HmacProv, out IBuffer keyBuff, out IBuffer inputBuff)
        {
            keyBuff = CryptographicBuffer.ConvertStringToBinary(key, BinaryStringEncoding.Utf8);
            inputBuff = CryptographicBuffer.ConvertStringToBinary(input, BinaryStringEncoding.Utf8);

            string algorithm = "";
            switch (algor)
            {
                case HmacAlgorithms.SHA1:
                    algorithm = MacAlgorithmNames.HmacSha1;
                    break;
                case HmacAlgorithms.SHA256:
                    algorithm = MacAlgorithmNames.HmacSha256;
                    break;
                case HmacAlgorithms.SHA384:
                    algorithm = MacAlgorithmNames.HmacSha384;
                    break;
                case HmacAlgorithms.SHA512:
                    algorithm = MacAlgorithmNames.HmacSha512;
                    break;
            }

            HmacProv = MacAlgorithmProvider.OpenAlgorithm(algorithm);
            hmacKey = HmacProv.CreateKey(keyBuff);
        }
    }
}
