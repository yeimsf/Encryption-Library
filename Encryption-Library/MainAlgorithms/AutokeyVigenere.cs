using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{
    public static class AutokeyVigenere
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
            string key = "";
            for (int i = 0; i < cipherText.Length; i++)
                key += char.ConvertFromUtf32(vigTable[plainText[i] % 65].IndexOf(cipherText[i]) + 65)[0];
            for (int i = 0; i < plainText.Length; i++)
            {
                int x = key.Length - 1;
                plainText = plainText.Remove(plainText.Length - 1,1);
                int remFromInd = key.IndexOf(plainText);
                if (remFromInd >= 0)
                    key = key.Remove(remFromInd, key.Length - remFromInd);
            }
            return key.ToLower();
        }

        public static string Decrypt(string cipherText, string key)
        {
            init_Table();
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText += char.ConvertFromUtf32(vigTable[key[i] % 65].IndexOf(cipherText[i]) + 65)[0];
                key += plainText[i];
            }
            return plainText.ToLower();
        }

        public static string Encrypt(string plainText, string key)
        {
            init_Table();
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            string cipherText = "";
            int keyLength = key.Length;
            for (int i = 0; (i + keyLength - 1)  < plainText.Length; i++)
                key += plainText[i % plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
                cipherText += vigTable[plainText[i] % 65][key[i] % 65];
            return cipherText;
        }
    }
}
