using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace  Encryption_Library
{
    public static class Columnar
    {
        public static List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            List<List<char>> keyMatrix = new List<List<char>>();
            int col = 0, row = 0, counter = 0, found = 0, counter2 = 1;
            if (cipherText[0] == plainText[0])
            {
                for (int i = 1; i < plainText.Length; i++)
                {
                    if (plainText[i] == cipherText[1])
                    {
                        col = i;
                        row = (int)Math.Round((Convert.ToDouble(plainText.Length) / Convert.ToDouble(col)));
                        break;
                    }
                }
            }
            else
            {
                for(int i = 1;i < plainText.Length;i++)
                {
                    if(cipherText[0] == plainText[i])
                    {
                        if (cipherText[1] == plainText[i + 1])
                            i++;
                        for(int j = i+2;j < plainText.Length;j++)
                        {
                            if(cipherText[1] == plainText[j])
                            {
                                col = j-i;
                                row = (int)Math.Round((Convert.ToDouble(plainText.Length) / Convert.ToDouble(col)));
                                found = 1;
                                break;
                            }
                        }
                    }
                    if (found == 1)
                        break;
                }
            }
            for(int i = 0;i < row;i++)
            {
                List<char> rowMat = new List<char>();
                for (int j = 0; j < col; j++)
                {
                    if (counter >= plainText.Length)
                    {
                        rowMat.Add('x');
                        continue;
                    }
                    rowMat.Add(plainText[counter++]);
                }
                keyMatrix.Add(rowMat);
            }
            int[] key = new int[col];
            for (int i = 0;i < cipherText.Length - 1;i+=row)
            {
                for(int j = 0;j < col;j++)
                {
                    if (cipherText[i] == keyMatrix[0][j] && cipherText[i + 1] == keyMatrix[1][j])
                    {
                        key[j] = counter2;
                        break;
                    }
                }
                counter2++;
            }
            return key.ToList<int>();
        }

        public static string Decrypt(string cipherText, List<int> key)
        {
            string plain = "";
            int coulmns = key.Count;
            double size = cipherText.Length;
            double arr_size = size / coulmns;
            arr_size = Math.Ceiling(arr_size);
            size = (int)arr_size;
            char[,] pt = new char[(int)size, coulmns];
            int current_row = 0;
            int current_coulmn = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                pt[current_row, current_coulmn] = cipherText[i];
                if (current_row == (int)size - 1)
                {
                    current_row = 0;
                    current_coulmn++;
                }
                else
                    current_row++;
            }
            for (int i = 0; i < (int)size; i++)
            {
                for (int j = 0; j < coulmns; j++)
                {
                    if (pt[i, j] == '\0')
                        pt[i, j] = 'x';
                }
            }
            for (int i = 0; i < (int)size; i++)
            {
                for (int j = 0; j < (int)coulmns; j++)
                {
                    int col = key.ElementAt(j);
                    plain += pt[i, col-1];
                }
            }
            return plain;
        }

        public static string Encrypt(string plainText, List<int> key)
        { 
            string cipher = "";
            int coulmns = key.Count;
            double size = plainText.Length;
            double arr_size = size / coulmns;
            arr_size = Math.Ceiling(arr_size);
            size = (int)arr_size;
            char[,] pt = new char[(int)size, coulmns];
            int current_row = 0;
            int current_coulmn = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                pt[current_row, current_coulmn] = plainText[i];
                if (current_coulmn == coulmns-1)
                {
                    current_coulmn = 0;
                    current_row++;
                }
                else
                    current_coulmn++;
            }
            for (int i = 0; i < (int)size; i++)
            {
                for (int j = 0; j <coulmns; j++)
                {
                    if (pt[i, j] == '\0')
                        pt[i, j] = 'x';
                }
            }
            for (int i = 0; i < coulmns; i++)
            {
                int col = key.IndexOf(i + 1);
                for (int j = 0; j < (int)size; j++)
                    cipher += pt[j, col];
            }
            return cipher;
        }
    }
}
