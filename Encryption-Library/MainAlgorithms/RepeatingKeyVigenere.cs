using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{
    public static class RepeatingkeyVigenere
    {
        private static List<List<char>> vigTable;
        private static void init_Table()
        {
            vigTable = new List<List<char>>();
            int alpha = 65;
            for (int i = 0; i < 26; i++)
            {
                List<char> alpha_Row = new List<char>();
                for (int j = 0; j < 26; j++)
                    alpha_Row.Insert(j, char.ConvertFromUtf32(((alpha + j - 65) % 26) + 65)[0]);
                alpha++;
                vigTable.Add(alpha_Row);
            }
        }
        public static string Analyse(string plainText, string cipherText)
        {
            init_Table();
            cipherText = cipherText.ToUpper();
            plainText = plainText.ToUpper();
            string key = "",tempK = "";
            for (int i = 0; i < cipherText.Length; i++)
                key += char.ConvertFromUtf32(vigTable[plainText[i] % 65].IndexOf(cipherText[i]) + 65)[0];
            int keyLength = key.Length, tempInd = 0;
            for (int i = 0; i < keyLength; i++)
            {
                tempK = tempK.Insert(i, key[i].ToString());
                tempInd = key.IndexOf(tempK, i+1);
                if (tempInd == tempK.Length)
                {
                    key = key.Remove(tempK.Length, key.Length - tempK.Length);
                    break;
                }
            }
            return key.ToLower();
        }

        public static string Decrypt(string cipherText, string key)
        {
            init_Table();
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            string plainText = "", newKey = "";
            for (int i = 0; i < cipherText.Length; i++)
                newKey += key[i % key.Length];
            for (int i = 0; i < cipherText.Length; i++)
                plainText += char.ConvertFromUtf32(vigTable[newKey[i] % 65].IndexOf(cipherText[i]) + 65)[0];
            return plainText;
        }

        public static string Encrypt(string plainText, string key)
        {
            init_Table();
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            string newKey = "", cipherText = "";
            for(int i = 0;i < plainText.Length;i++)
                newKey += key[i % key.Length];
            for (int i = 0; i < plainText.Length; i++)
                cipherText += vigTable[plainText[i] % 65][newKey[i] % 65];
            return cipherText;
        }
    }
}