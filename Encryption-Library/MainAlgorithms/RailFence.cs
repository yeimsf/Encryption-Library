using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{
    public static class RailFence
    {
        public static int Analyse(string plainText, string cipherText)
        {
            
            int key = 0;
            cipherText = cipherText.ToLower();
            for (int i = 2; i < plainText.Length; i++)
            {
                if (cipherText[1] == plainText[i])
                {
                    key = i;
                    break;
                }
            }
            return key;
        }

        public static string Decrypt(string cipherText, int key)
        {
            string plain = "";
            double size = cipherText.Length;
            double arr_size = size / key;
            arr_size = Math.Ceiling(arr_size);
            size = (int)arr_size;
            char[,] pt = new char[key, (int)size];
            int current_row = 0;
            int current_coulmn = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                pt[current_row, current_coulmn] = cipherText[i];
                if (current_coulmn == size - 1)
                {
                    current_coulmn = 0;
                    current_row++;
                }
                else
                    current_coulmn++;
            }
            current_row = 0;
            current_coulmn = 0;

            for (int i = 0; i < cipherText.Length; i++)
            {
                plain += pt[current_row, current_coulmn];
                if (current_row == key - 1)
                {
                    current_row = 0;
                    if (current_coulmn == size - 1)
                    {
                        current_coulmn = 0;
                        current_row++;
                    }
                    else
                        current_coulmn++;
                }
                else
                    current_row++;
            }
            plain = plain.ToLower();
            return plain;
        }

        public static string Encrypt(string plainText, int key)
        {
            string cipher = "";
            double size = plainText.Length;
            double arr_size = size / key;
            arr_size = Math.Ceiling(arr_size);
            size = (int)arr_size;
            char[,]pt=new char[key,(int)size];
            int current_row = 0;
            int current_coulmn = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                pt[current_row, current_coulmn] = plainText[i];
                if (current_row == key - 1)
                {
                    current_row = 0;
                    if (current_coulmn == size - 1)
                    {
                        current_coulmn = 0;
                        current_row++;  
                    }
                    else
                        current_coulmn++;
                }     
                else 
                    current_row++;
            }
            current_row = 0;
            current_coulmn = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (pt[current_row, current_coulmn] == '\0')
                {
                    current_coulmn = 0;
                    current_row++;
                }
                cipher+= pt[current_row, current_coulmn];
                if (current_coulmn == size - 1)
                {
                    current_coulmn = 0;
                    current_row++;
                }
                else
                    current_coulmn++;
            }
            cipher = cipher.ToUpper();
            return cipher;
        }
    }
}
