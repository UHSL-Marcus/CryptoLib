using System.Security.Cryptography;
using System.Text;

namespace CryptoLib
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
            byte[] hash = null;
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            switch (algor)
            {
                case HmacAlgorithms.SHA1:
                    hash = new HMACSHA1(keyBytes).ComputeHash(inputBytes);
                    break;
                case HmacAlgorithms.SHA256:
                    hash = new HMACSHA256(keyBytes).ComputeHash(inputBytes);
                    break;
                case HmacAlgorithms.SHA384:
                    hash = new HMACSHA384(keyBytes).ComputeHash(inputBytes);
                    break;
                case HmacAlgorithms.SHA512:
                    hash = new HMACSHA512(keyBytes).ComputeHash(inputBytes);
                    break;
            }
           
            StringBuilder hex = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash)
                hex.AppendFormat("{0:x2}", b);

            return hex.ToString();
        }

        public static bool ValidateHash(string input, string key, string hmac, HmacAlgorithms algor)
        {
            string calcHmac = Hash(input, key, algor);
            if (calcHmac.Equals(hmac))
                return true;
            else
                return false;
        }
    }
}
