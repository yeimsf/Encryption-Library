using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{
    public static class PlayFair
    {
        public static string Decrypt(string cipherText, string key)
        {
            int it_row_ind = 0, it_col_ind = 0;
            char[,] map = new char[5, 5];
            bool[] alphaTaken = new bool[25];
            string P_T = "", P_T_Clean = "", alphabet = "abcdefghiklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();
            List<Tuple<char, char>> C_T = new List<Tuple<char, char>>();
            for (int i = 0; i < cipherText.Length - 1; i += 2)
                C_T.Add(new Tuple<char, char>(cipherText[i], cipherText[i + 1]));
            for (int i = 0; i < key.Length; i++)
            {
                if (!alphaTaken[alphabet.IndexOf(key[i])])
                { 
                    if (key[i] == 'j')
                    {
                        alphaTaken[8] = true;
                        map[it_row_ind, it_col_ind] = 'j';
                        if (it_col_ind == 4)
                            it_row_ind++;
                        it_col_ind = (it_col_ind + 1) % 5;
                    }
                    else
                    {
                        map[it_row_ind, it_col_ind] = key[i];
                        alphaTaken[alphabet.IndexOf(key[i])] = true;
                        if (it_col_ind == 4)
                            it_row_ind++;
                        it_col_ind = (it_col_ind + 1) % 5;
                    }
                }
            }
            for (int i = 0; i <= 24; i++)
            {
                if (!alphaTaken[i])
                {
                    map[it_row_ind, it_col_ind] = alphabet[i];
                    alphaTaken[alphabet.IndexOf(alphabet[i])] = true;
                    if (it_col_ind == 4)
                        it_row_ind++;
                    it_col_ind = (it_col_ind + 1) % 5;
                }
            }
            Tuple<int, int> first_ind = new Tuple<int, int>(-1,-1), second_ind = new Tuple<int, int>(-1, -1);
            foreach (var couple in C_T)
            {
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                        if (couple.Item1 == map[i, j])
                            first_ind = new Tuple<int, int>(i, j);
                        else if (couple.Item2 == map[i, j])
                            second_ind = new Tuple<int, int>(i, j);
                }
                if (first_ind.Item2 == second_ind.Item2)
                    P_T += map[((first_ind.Item1 - 1) + 5) % 5, first_ind.Item2].ToString() + map[((second_ind.Item1 - 1) + 5) % 5, second_ind.Item2].ToString();
                else if (first_ind.Item1 == second_ind.Item1)
                    P_T += map[first_ind.Item1, ((first_ind.Item2 - 1) + 5) % 5].ToString() + map[second_ind.Item1, ((second_ind.Item2 - 1) + 5) % 5].ToString();
                else
                    P_T += map[first_ind.Item1, second_ind.Item2].ToString() + map[second_ind.Item1, first_ind.Item2].ToString();
            }
            for (int i = 0; i < P_T.Length - 2; i += 2)
                if (P_T[i] == P_T[i + 2] && P_T[i + 1] == 'x' && (i + 1) % 2 == 1)
                    P_T_Clean += P_T[i].ToString();
                else
                    P_T_Clean += P_T[i].ToString() + P_T[i + 1].ToString();
            P_T_Clean += P_T[P_T.Length - 2].ToString() + P_T[P_T.Length - 1].ToString();
            if (P_T_Clean[P_T_Clean.Length - 1] == 'x')
                P_T_Clean = P_T_Clean.Remove(P_T_Clean.Length - 1, 1);
            return P_T_Clean;
        }

        public static string Encrypt(string plainText, string key)
        {
            int it_row_ind = 0, it_col_ind = 0;
            char[,] map = new char[5, 5];
            bool[] alphaTaken = new bool[25];
            string C_T = "", alphabet = "abcdefghiklmnopqrstuvwxyz";
            plainText = plainText.ToLower();
            List<Tuple<char, char>> P_T = new List<Tuple<char, char>>();
            for (int i = 0; i < key.Length; i++)
            {
                if (!alphaTaken[alphabet.IndexOf(key[i])])
                {
                    if (key[i] == 'j')
                    {
                        alphaTaken[8] = true;
                        map[it_row_ind, it_col_ind] = 'j';
                        if (it_col_ind == 4)
                            it_row_ind++;
                        it_col_ind = (it_col_ind + 1) % 5;
                    }
                    else
                    {
                        map[it_row_ind, it_col_ind] = key[i];
                        alphaTaken[alphabet.IndexOf(key[i])] = true;
                        if (it_col_ind == 4)
                            it_row_ind++;
                        it_col_ind = (it_col_ind + 1) % 5;
                    }
                }
            }
            for (int i = 0; i <= 24; i++)
            {
                if (!alphaTaken[i])
                {
                    map[it_row_ind, it_col_ind] = alphabet[i];
                    alphaTaken[alphabet.IndexOf(alphabet[i])] = true;
                    if (it_col_ind == 4)
                        it_row_ind++;
                    it_col_ind = (it_col_ind + 1) % 5;
                }
            }
            for (int i = 0; i < plainText.Length; i += 2)
            {
                if(i == plainText.Length - 1)
                    P_T.Add(new Tuple<char, char>(plainText[plainText.Length - 1], 'x'));
                else if (plainText[i] == plainText[i + 1])
                {
                    P_T.Add(new Tuple<char, char>(plainText[i], 'x'));
                    i--;
                }
                else
                    P_T.Add(new Tuple<char, char>(plainText[i], plainText[i + 1]));
            }
            Tuple<int, int> first_ind = new Tuple<int, int>(-1,-1), second_ind = new Tuple<int, int>(-1, -1);
            foreach (var couple in P_T)
            {
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                        if (couple.Item1 == map[i, j])
                            first_ind = new Tuple<int, int>(i, j);
                        else if (couple.Item2 == map[i, j])
                            second_ind = new Tuple<int, int>(i, j);
                }
                if (first_ind.Item2 == second_ind.Item2)
                    C_T += map[(first_ind.Item1 + 1) % 5, first_ind.Item2].ToString() + map[(second_ind.Item1 + 1) % 5, second_ind.Item2].ToString();
                else if (first_ind.Item1 == second_ind.Item1)
                    C_T += map[first_ind.Item1, (first_ind.Item2 + 1) % 5].ToString() + map[second_ind.Item1, (second_ind.Item2 + 1) % 5].ToString();
                else
                    C_T += map[first_ind.Item1, second_ind.Item2].ToString() + map[second_ind.Item1, first_ind.Item2].ToString();
            }
            C_T = C_T.ToUpper();
            return C_T;
        }
    }
}
