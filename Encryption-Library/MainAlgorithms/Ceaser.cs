using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{

    public static class Ceaser
    {
        public static string Encrypt(string plainText, int key)
        {
            int C_T_index = 0;
            string C_T = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j <= 25; j++)
                {
                    if (plainText[i] == alphabet[j])
                    {
                        C_T_index = (j + key) % 26;
                        break;
                    }
                }
                C_T += alphabet[C_T_index].ToString().ToUpper();
            }
            return C_T;
        }

        public static string Decrypt(string cipherText, int key)
        {
            string P_T = ""; int P_T_index = 0;
            string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j <= 25; j++)
                {
                    if (cipherText[i] == alphabet[j])
                    {
                        P_T_index = (j - key) % 26;
                        break;
                    }
                }
                if (P_T_index < 0)
                    P_T_index += alphabet.Length;
                P_T += alphabet[P_T_index].ToString().ToLower();
            }
            return P_T;
        }

        public static int Analyse(string plainText, string cipherText)
        {
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            int key, P_T_index=0, C_T_index=0;
            cipherText = cipherText.ToLower();
            for (int i = 0; i < alphabet.Length; i++)
            {
                if (plainText[0]==alphabet[i])
                    P_T_index = i;
                if (cipherText[0]==alphabet[i])
                    C_T_index = i;
            }
            key = C_T_index - P_T_index;
            if (key<0)
                key += alphabet.Length;
            return key;
        }
    }
}
