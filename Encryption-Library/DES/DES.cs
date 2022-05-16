using System;
using System.Collections.Generic;
using System.Collections;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// IN PROGRESS
namespace Encryption_Library
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public static class DES
    {
        private static int[,] PC_1 =
        {
            { 57, 49, 41, 33, 25, 17, 9 },
            { 1, 58, 50, 42, 34, 26, 18 },
            { 10, 2, 59, 51, 43, 35, 27 },
            { 19, 11, 3, 60, 52, 44, 36 },
            { 63, 55, 47, 39, 31, 23, 15 },
            { 7, 62, 54, 46, 38, 30, 22 },
            { 14, 6, 61, 53, 45, 37, 29 },
            { 21, 13, 5, 28, 20, 12, 4 }
        };
        private static int[] ShiftIter = { 1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28 };
        private static int[,] PC_2 =
        {
            { 14, 17, 11, 24, 1, 5 },
            { 3, 28, 15, 6, 21, 10 },
            { 23, 19, 12, 4, 26, 8 },
            { 16, 7, 27, 20, 13, 2 },
            { 41, 52, 31, 37, 47, 55 },
            { 30, 40, 51, 45, 33, 48 },
            { 44, 49, 39, 56, 34, 53 },
            { 46, 42, 50, 36, 29, 32 }
        };
        private static int[,] IP =
        {
            { 58, 50, 42, 34, 26, 18, 10, 2 },
            { 60, 52, 44, 36, 28, 20, 12, 4 },
            { 62, 54, 46, 38, 30, 22, 14, 6 },
            { 64, 56, 48, 40, 32, 24, 16, 8 },
            { 57, 49, 41, 33, 25, 17, 9,  1 },
            { 59, 51, 43, 35, 27, 19, 11, 3 },
            { 61, 53, 45, 37, 29, 21, 13, 5 },
            { 63, 55, 47, 39, 31, 23, 15, 7 }
        };
        private static int[,] E =
        {
            { 32, 1, 2, 3, 4, 5 },
            { 4, 5, 6, 7, 8, 9 },
            { 8, 9, 10, 11, 12, 13 },
            { 12, 13, 14, 15, 16, 17 },
            { 16, 17, 18, 19, 20, 21 },
            { 20, 21, 22, 23, 24, 25 },
            { 24, 25, 26, 27, 28, 29 },
            { 28, 29, 30, 31, 32, 1 },
        };
        private static byte[,,] SBoxes =
        {
           {
                { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
            },
            {
                { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
            },
            { 
                { 10, 0, 9 ,14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
            },
            { 
                { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
            },
            {
                { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
            },
            { 
                { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
            },
            { 
                { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
            },
            { 
                { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
            }
        };
        private static int[,] P =
        {
            { 16,  7, 20, 21},
            { 29, 12, 28, 17},
            { 1, 15, 23, 26 },
            { 5, 18, 31, 10 },
            { 2, 8, 24, 14 },
            { 32, 27, 3, 9 },
            { 19, 13, 30, 6 },
            { 22, 11, 4, 25 }
        };
        public static int[,] IP_Inverse =
        {
            { 40, 8, 48, 16, 56, 24, 64, 32 },
            { 39, 7, 47, 15, 55, 23, 63, 31 },
            { 38, 6, 46, 14, 54, 22, 62, 30 },
            { 37, 5, 45, 13, 53, 21, 61, 29 },
            { 36, 4, 44, 12, 52, 20, 60, 28 },
            { 35, 3, 43, 11, 51, 19, 59, 27 },
            { 34, 2, 42, 10, 50, 18, 58, 26 },
            { 33, 1, 41, 9, 49, 17, 57, 25 }
        };
        private static List<byte[]> Keys;
        private static byte[] plainBlock = new byte[64], cipherBlock = new byte[64], keyBlock = new byte[64];

        public static string Decrypt(string cipherText, string key)
        {
            string plainText = "0x";
            key = key.Remove(0, 2);
            cipherText = cipherText.Remove(0, 2);

            byte[] cipherBytes = StringToByteArray(cipherText), keyBytes = StringToByteArray(key);

            BitArray cipherBlockBits = new BitArray(cipherBytes), keyBlockBits = new BitArray(keyBytes);

            for (int i = 0; i < 64; i++)
            {
                if (cipherBlockBits[i] == false)
                    cipherBlock[i] = 0x00;
                else if (cipherBlockBits[i] == true)
                    cipherBlock[i] = 0x01;
                if (keyBlockBits[i] == false)
                    keyBlock[i] = 0x00;
                else if (keyBlockBits[i] == true)
                    keyBlock[i] = 0x01;
            }

            KeySchedule();
            throw new NotImplementedException();
        }

        public static string Encrypt(string plainText, string key)
        {
            string cipherText = "0x";
            key = key.Remove(0, 2);
            plainText = plainText.Remove(0, 2);

            byte[] plainBytes = StringToByteArray(plainText), keyBytes = StringToByteArray(key);

            BitArray plainBlockBits = new BitArray(plainBytes), keyBlockBits = new BitArray(keyBytes);

            
            for(int i = 0;i < 64;i++)
            {
                if (plainBlockBits[i] == false)
                    plainBlock[i] = 0x00;
                else if (plainBlockBits[i] == true)
                    plainBlock[i] = 0x01;
                if (keyBlockBits[i] == false)
                    keyBlock[i] = 0x00;
                else if (keyBlockBits[i] == true)
                    keyBlock[i] = 0x01;
            }

            KeySchedule();
            Encode();
            throw new NotImplementedException();
        }
        private static byte[] StringToByteArray(string text)
        {
            return Enumerable.Range(0, text.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(text.Substring(x, 2), 16))
                             .ToArray();
        }
        private static void KeySchedule()
        {
            // PC-1
            byte[] subKey = new byte[56];
            int counter = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    subKey[counter] = keyBlock[PC_1[i, j] - 1];
                    counter++;
                }
            }
            // Key Split Into Two 28 Bit Halves
            byte[] C0 = new byte[28], D0 = new byte[28];
            for(int i = 0;i < 56;i++)
            {
                if (i >= 28)
                    D0[i - 28] = subKey[i];
                else
                    C0[i] = subKey[i];
            }
            // Key Rounds Generation
            Keys = new List<byte[]>();
            Keys.Add(subKey);
            for(int round = 0;round < 16;round++)
            {
                subKey = new byte[56];
                byte[] CInd = new byte[28], DInd = new byte[28];
                if (round != 15)
                {
                    for (int i = ShiftIter[round]; i < 28; i++)
                    {
                        CInd[i - ShiftIter[round]] = C0[i];
                        DInd[i - ShiftIter[round]] = D0[i];
                    }
                    for (int i = 0; i < ShiftIter[round]; i++)
                    {
                        CInd[27 - ShiftIter[round]] = C0[i];
                        DInd[27 - ShiftIter[round]] = D0[i];
                    }
                }
                else if (round == 15)
                {
                    CInd = C0;
                    DInd = D0;
                }
                for (int i = 0; i < 56; i++)
                {
                    if (i >= 28)
                        subKey[i] = DInd[i - 28];
                    else
                        subKey[i] = CInd[i];
                }
                byte[] subKeyFin = new byte[48];
                counter = 0;
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        subKeyFin[counter] = subKey[PC_2[i, j] - 1];
                        counter++;
                    }
                }
                Keys.Add(subKeyFin);
            }
        }
        private static void Encode()
        {
            byte[] plainBlockPermutated = new byte[64];
            int counter = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    plainBlockPermutated[counter] = plainBlock[IP[i, j] - 1];
                    counter++;
                }
            }
            // Plain Message Split Into Two 28 Bit Halves
            byte[] L0 = new byte[32], R0 = new byte[32];
            for (int i = 0; i < 64; i++)
            {
                if (i >= 32)
                    R0[i - 32] = plainBlockPermutated[i];
                else
                    L0[i] = plainBlockPermutated[i];
            }

            for (int round = 0; round < 16; round++)
            {
                byte[] LInd = new byte[32], RInd = new byte[32];
                if (round == 0)
                {
                    byte[] tmp = new byte[48];
                    LInd = R0;
                    counter = 0;
                    for (int i = 0; i < 8; i++)
                    {
                        for (int j = 0; j < 6; j++)
                        {
                            tmp[counter] = R0[E[i, j] - 1];
                            counter++;
                        }
                    }
                    for (int i = 0; i < 48; i++)
                        tmp[i] ^= Keys[round + 1][i];
                    byte[] SBoxReturn = new byte[8], SboxReturnFin = new byte[32];
                    int SboxCounter = 0;
                    for(int i = 0;i < 48;i+=6)
                    {
                        int row = 0, col = 0;
                        if (tmp[i + 5] == 0x01)
                            row += 1;
                        if (tmp[i] == 0x01)
                            row += 2;
                        if (tmp[i + 4] == 0x01)
                            col += 1;
                        if (tmp[i + 3] == 0x01)
                            col += 2;
                        if (tmp[i + 2] == 0x01)
                            col += 4;
                        if (tmp[i + 1] == 0x01)
                            col += 8;
                        SBoxReturn[SboxCounter] = SBoxes[SboxCounter, row, col];
                    }
                    BitArray SboxReturnBits = new BitArray(SBoxReturn);
                    for (int i = 0; i < 32; i++)
                    {
                        if (SboxReturnBits[i] == false)
                            SboxReturnFin[i] = 0x00;
                        else if (SboxReturnBits[i] == true)
                            SboxReturnFin[i] = 0x01;
                    }
                    for (int i = 0; i < 32; i++)
                        RInd[i] = (byte)(L0[i]^SboxReturnFin[i]);
                    //for (int i = 0; i < 56; i++)
                    //{
                    //    if (i >= 28)
                    //        subKey[i] = DInd[i - 28];
                    //    else
                    //        subKey[i] = CInd[i];
                    //}
                }
                else
                {
                    byte[] tmp = new byte[48];
                    byte[] LIndTmp = LInd;
                    LInd = RInd;
                    counter = 0;
                    for (int i = 0; i < 8; i++)
                    {
                        for (int j = 0; j < 6; j++)
                        {
                            tmp[counter] = RInd[E[i, j] - 1];
                            counter++;
                        }
                    }
                    for (int i = 0; i < 48; i++)
                        tmp[i] ^= Keys[round + 1][i];
                    byte[] SBoxReturn = new byte[8], SboxReturnFin = new byte[32];
                    int SboxCounter = 0;
                    for (int i = 0; i < 48; i += 6)
                    {
                        int row = 0, col = 0;
                        if (tmp[i + 5] == 0x01)
                            row += 1;
                        if (tmp[i] == 0x01)
                            row += 2;
                        if (tmp[i + 4] == 0x01)
                            col += 1;
                        if (tmp[i + 3] == 0x01)
                            col += 2;
                        if (tmp[i + 2] == 0x01)
                            col += 4;
                        if (tmp[i + 1] == 0x01)
                            col += 8;
                        SBoxReturn[SboxCounter] = SBoxes[SboxCounter, row, col];
                    }
                    BitArray SboxReturnBits = new BitArray(SBoxReturn);
                    for (int i = 0; i < 32; i++)
                    {
                        if (SboxReturnBits[i] == false)
                            SboxReturnFin[i] = 0x00;
                        else if (SboxReturnBits[i] == true)
                            SboxReturnFin[i] = 0x01;
                    }
                    for (int i = 0; i < 32; i++)
                        RInd[i] = (byte)(LIndTmp[i] ^ SboxReturnFin[i]);
                }
            }

        }
    }
}
