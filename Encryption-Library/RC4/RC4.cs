using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public static class RC4
    {
        public static string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            if (cipherText[0] == '0' && cipherText[1] == 'x')
            {
                cipherText = cipherText.Remove(0, 2);
                key = key.Remove(0, 2);
                byte[] plaintTextBytes = StringToByteArray(cipherText);
                byte[] keyBytes = StringToByteArray(key);
                byte[] s = new byte[256];
                byte[] t = new byte[256];
                byte[] ci = new byte[plaintTextBytes.Length];
                string cipher = "0x";
                int counter = 0, j = 0, index = 0, l = 0;
                byte temp;
                //Initialization of two arrays
                for (int i = 0; i < s.Length; i++)
                {
                    s[i] = (byte)i;
                    t[i] = keyBytes[counter];
                    counter++;
                    if (counter == keyBytes.Length)
                    {
                        counter = 0;
                    }
                }
                //KSA algorithm
                for (int i = 0; i < 256; i++)
                {
                    j = (j + s[i] + t[i]) % 256;
                    temp = s[i];
                    s[i] = s[j];
                    s[j] = temp;
                }
                //PNGA algorithm
                j = 0;
                byte[] k = new byte[plaintTextBytes.Length];
                for (int i = 0; i < k.Length; i++)
                {
                    index = (index + 1) % 256;
                    j = (j + s[index]) % 256;
                    temp = s[index];
                    s[index] = s[j];
                    s[j] = temp;
                    byte te = (byte)((s[index] + s[j]) % 256);
                    k[l] = s[te];
                    l++;
                }
                for (int i = 0; i < plaintTextBytes.Length; i++)
                {
                    ci[i] = (byte)(plaintTextBytes[i] ^ k[i]);
                }

                cipher += BitConverter.ToString(ci).Replace("-", "");
                return cipher;
            }
            else
            {
                byte[] s = new byte[256];
                byte[] t = new byte[256];
                byte[] ci = new byte[cipherText.Length];
                string cipher = "";
                int counter = 0, j = 0, index = 0, l = 0;
                byte temp;
                //Initialization of two arrays
                for (int i = 0; i < s.Length; i++)
                {
                    s[i] = (byte)i;
                    t[i] = (byte)key[counter];
                    counter++;
                    if (counter == key.Length)
                    {
                        counter = 0;
                    }
                }
                //KSA algorithm
                for (int i = 0; i < 256; i++)
                {
                    j = (j + s[i] + t[i]) % 256;
                    temp = s[i];
                    s[i] = s[j];
                    s[j] = temp;
                }
                //PNGA algorithm
                j = 0;
                byte[] k = new byte[cipherText.Length];
                for (int i = 0; i < k.Length; i++)
                {
                    index = (index + 1) % 256;
                    j = (j + s[index]) % 256;
                    temp = s[index];
                    s[index] = s[j];
                    s[j] = temp;
                    byte te = (byte)((s[index] + s[j]) % 256);
                    k[l] = s[te];
                    l++;
                }
                for (int i = 0; i < cipherText.Length; i++)
                {
                    ci[i] = (byte)(cipherText[i] ^ k[i]);
                }
                cipher = Encoding.UTF8.GetString(ci);
                return cipher;
            }
        }

        public static string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            if (plainText[0]=='0'&&plainText[1]=='x')
            {
                plainText = plainText.Remove(0, 2);
                key = key.Remove(0, 2);
                byte[] plaintTextBytes = StringToByteArray(plainText);
                byte[] keyBytes = StringToByteArray(key);
                byte[] s = new byte[256];
                byte[] t = new byte[256];
                byte[] ci = new byte[plaintTextBytes.Length];
                string cipher = "0x";
                int counter = 0, j = 0, index = 0, l = 0;
                byte temp;
                //Initialization of two arrays
                for (int i = 0; i < s.Length; i++)
                {
                    s[i] = (byte)i;
                    t[i] = keyBytes[counter];
                    counter++;
                    if (counter == keyBytes.Length)
                    {
                        counter = 0;
                    }
                }
                //KSA algorithm
                for (int i = 0; i < 256; i++)
                {
                    j = (j + s[i] + t[i]) % 256;
                    temp = s[i];
                    s[i] = s[j];
                    s[j] = temp;
                }
                //PNGA algorithm
                j = 0;
                byte[] k = new byte[plaintTextBytes.Length];
                for (int i = 0; i < k.Length; i++)
                {
                    index = (index + 1) % 256;
                    j = (j + s[index]) % 256;
                    temp = s[index];
                    s[index] = s[j];
                    s[j] = temp;
                    byte te = (byte)((s[index] + s[j]) % 256);
                    k[l] = s[te];
                    l++;
                }
                for (int i = 0; i < plaintTextBytes.Length; i++)
                {
                    ci[i] = (byte)(plaintTextBytes[i] ^ k[i]);
                }
                
                cipher += BitConverter.ToString(ci).Replace("-", "");
                return cipher;
            }
            else
            {
                byte[] s = new byte[256];
                byte[] t = new byte[256];
                byte[] ci = new byte[plainText.Length];
                string cipher = "";
                int counter = 0, j = 0, index = 0, l = 0;
                byte temp;
                //Initialization of two arrays
                for (int i = 0; i < s.Length; i++)
                {
                    s[i] = (byte)i;
                    t[i] = (byte)key[counter];
                    counter++;
                    if (counter == key.Length)
                    {
                        counter = 0;
                    }
                }
                //KSA algorithm
                for (int i = 0; i < 256; i++)
                {
                    j = (j + s[i] + t[i]) % 256;
                    temp = s[i];
                    s[i] = s[j];
                    s[j] = temp;
                }
                //PNGA algorithm
                j = 0;
                byte[] k = new byte[plainText.Length];
                for (int i = 0; i < k.Length; i++)
                {
                    index = (index + 1) % 256;
                    j = (j + s[index]) % 256;
                    temp = s[index];
                    s[index] = s[j];
                    s[j] = temp;
                    byte te = (byte)((s[index] + s[j]) % 256);
                    k[l] = s[te];
                    l++;
                }
                for (int i = 0; i < plainText.Length; i++)
                {
                    ci[i] = (byte)(plainText[i] ^ k[i]);
                }
                cipher = Encoding.UTF7.GetString(ci);
                return cipher;
            }
            
        }
        private static byte[] StringToByteArray(string text)
        {
            return Enumerable.Range(0, text.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(text.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
