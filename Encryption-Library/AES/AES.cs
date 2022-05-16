using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Encryption_Library
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public static class AES
    {
        private static List<List<byte>> plainBlock = new List<List<byte>>(), cipherBlock = new List<List<byte>>(), keyBlock = new List<List<byte>>(), operationsBlock = new List<List<byte>>(),returnedFromMixColumns=new List<List<byte>>();
        private static List<List<List<byte>>> keySchedInfo = new List<List<List<byte>>>();
        private static byte[,] InvMixCols =
        {
            { 0x0e, 0x0b, 0x0d, 0x09 },
            { 0x09, 0x0e, 0x0b, 0x0d },
            { 0x0d, 0x09, 0x0e, 0x0b },
            { 0x0b, 0x0d, 0x09, 0x0e }
        };
        private static byte[,] MixCols =
        {
            { 0x02, 0x03, 0x01, 0x01 },
            { 0x01, 0x02, 0x03, 0x01 },
            { 0x01, 0x01, 0x02, 0x03 },
            { 0x03, 0x01, 0x01, 0x02 }
        };
        private static byte[,] Rcon =
        {
            { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
        };
        private static byte[,] Sblock =
        {//       0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
                {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, //0 
                {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, //1
                {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, //2 
                {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, //3 
                {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, //4
                {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, //5
                {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, //6
                {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, //7
                {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, //8
                {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, //9
                {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, //A
                {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, //B
                {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, //C
                {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, //D
                {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, //E
                {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}  //F
        }
        , SblockInverse =
        {//       0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F      
                {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB}, //0
                {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB}, //1
                {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E}, //2
                {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25}, //3
                {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92}, //4
                {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84}, //5
                {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06}, //6
                {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B}, //7
                {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73}, //8
                {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E}, //9
                {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B}, //A
                {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4}, //B
                {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F}, //C
                {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF}, //D
                {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61}, //E
                {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}  //F
        };
        public static string Decrypt(string cipherText, string key)
        {
            string plainText = "0x";

            InitAESComps(key, cipherText, "");
            KeyScheduler();

            // Decryption Algorithm Starts Here
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    cipherBlock[i][j] = (byte)(cipherBlock[i][j] ^ keySchedInfo[10][i][j]);
            for (int i = 9; i >= 0; i--)
            {
                InverseShiftRows();
                InverseSubBytes();
                for (int j = 0; j < 4; j++)
                    for (int k = 0; k < 4; k++)
                        cipherBlock[j][k] = (byte)(cipherBlock[j][k] ^ keySchedInfo[i][j][k]);
                if(i != 0)
                    InverseMixCols();
            }
            for(int i = 0;i < 4;i++)
                for(int j = 0; j < 4; j++)
                    plainText += BitConverter.ToString(new[] { cipherBlock[j][i] }).Replace("-", "");
            return plainText.ToLower();
        }

        public static string Encrypt(string plainText, string key)
        {
            string cipherText = "0x";
            InitAESComps(key, "", plainText);
            KeyScheduler();
            // Encryption Algorithm Starts Here
            initialAddRoundKey(plainBlock, keySchedInfo[0]);
            makeOperations(keySchedInfo);
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    cipherText += BitConverter.ToString(new[] { operationsBlock[j][i] }).Replace("-", "");
                }
            }
            return cipherText;
        }

        private static byte[] StringToByteArray(string text)
        {
            return Enumerable.Range(0, text.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(text.Substring(x, 2), 16))
                             .ToArray();
        }

        private static void InitAESComps(string key, string cipherText, string plainText)
        {
            keyBlock = new List<List<byte>>();
            cipherBlock = new List<List<byte>>();
            plainBlock = new List<List<byte>>();
            for(int i = 0;i < 4;i++)
            {
                keyBlock.Add(new List<byte> { 0x00, 0x00, 0x00, 0x00 });
                cipherBlock.Add(new List<byte> { 0x00, 0x00, 0x00, 0x00 });
                plainBlock.Add(new List<byte> { 0x00, 0x00, 0x00, 0x00 });
            }
            
            key = key.Remove(0, 2);
            List<byte> keyTextBs = StringToByteArray(key).ToList();

            // Decryption Mode
            if (plainText == "")
            {
                cipherText = cipherText.Remove(0, 2);
                List<byte> cipherTextBs = StringToByteArray(cipherText).ToList();
                int counter = 0;
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        keyBlock[j][i] = keyTextBs[counter];
                        cipherBlock[j][i] = cipherTextBs[counter];
                        counter++;
                    }
                }
            }
            // Encryption Mode
            else if(cipherText == "")
            {
                plainText = plainText.Remove(0, 2);
                List<byte> plainTextBs = StringToByteArray(plainText).ToList();
                int counter = 0;
                
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        keyBlock[j][i] = keyTextBs[counter];
                        plainBlock[j][i] = plainTextBs[counter];
                        counter++;
                    }
                }
            }
        }
        private static void KeyScheduler()
        {
            int wordCounter = 4;
            List<List<byte>> keyRound = keyBlock, tmp = new List<List<byte>>();
            for (int i = 0; i < 11; i++)
            {
                if (i == 0)
                    keySchedInfo.Add(keyRound);
                else
                {
                    tmp = keyRound;
                    keyRound = new List<List<byte>>(4);
                    for (int j = 0; j < 4; j++)
                        keyRound.Add(new List<byte> { 0, 0, 0, 0 });
                    for (int j = 0; j < 4; j++)
                    {
                        if (wordCounter % 4 == 0)
                        {
                            for (int k = 0; k < 4; k++)
                            {
                                byte sblockRes = Sblock[(tmp[(k + 1) % 4][3] >> 4), (tmp[(k + 1) % 4][3] & 0x0F)];
                                keyRound[k][j] = (byte)(sblockRes ^ tmp[k][j] ^ Rcon[k,i - 1]);
                            }
                        }
                        else
                            for (int k = 0; k < 4; k++)
                                keyRound[k][j] = (byte)(tmp[k][j] ^ keyRound[k][j - 1]);
                        wordCounter++;
                    }
                    keySchedInfo.Add(keyRound);
                }
            }
        }
        private static void initialAddRoundKey(List<List<byte>> plain, List<List<byte>> initialKey)
        {
            for (int i = 0; i < 4; i++)
            {
                operationsBlock.Add(new List<byte> { 0, 0, 0, 0 });
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    operationsBlock[j][i] = (byte)(plain[j][i] ^ initialKey[j][i]);
                }
            }
        }
        private static void makeOperations(List<List<List<byte>>> roundKey)
        {
            for (int i = 1; i < 10; i++)
            {
                subBytes(operationsBlock);
                shiftRows(operationsBlock);
                mixColumns(operationsBlock);
                addRoundKey(operationsBlock, roundKey[i]);
            }
            subBytes(operationsBlock);
            shiftRows(operationsBlock);
            addRoundKey(operationsBlock, roundKey[10]);
        }
        private static void subBytes(List<List<byte>> operationsMatrix)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int x = (operationsMatrix[i][j] >> 4);
                    int y = (operationsMatrix[i][j] & 0x0F);
                    byte sBlockSub = Sblock[x, y];
                    operationsMatrix[i][j] = sBlockSub;
                }
            }
            operationsBlock = operationsMatrix;
        }
        private static void shiftRows(List<List<byte>> operationsMatrix)
        {
            for (int i = 0; i < 4; i++)
            {
                if (i == 0)
                {
                    continue;
                }
                byte[] tmpRow = new byte[4];
                for (int j = 0; j < 4; j++)
                {
                    tmpRow[j] = operationsMatrix[i][j];
                }
                for (int j = 0; j < 4; j++)
                {
                    operationsMatrix[i][j] = tmpRow[(j + (4 + i)) % 4];
                }
            }
            operationsBlock = operationsMatrix;
        }
        private static void mixColumns(List<List<byte>> operationsMatrix)
        {
            returnedFromMixColumns = new List<List<byte>>();
            for (int i = 0; i < 4; i++)
            {
                returnedFromMixColumns.Add(new List<byte> { 0, 0, 0, 0 });
            }
            byte[] elements = new byte[] { 0, 0, 0, 0 };
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (MixCols[i, k] == 0x02)
                        {
                            elements[k] = MixColsMulti_2(operationsMatrix[k][j]);
                        }
                        else if (MixCols[i, k] == 0x03)
                        {
                            elements[k] = MixColsMulti_3(operationsMatrix[k][j]);
                        }
                        else
                        {
                            elements[k] = operationsMatrix[k][j];
                        }
                    }
                    returnedFromMixColumns[i][j] = (byte)(elements[0] ^ elements[1] ^ elements[2] ^ elements[3]);
                }
            }
            operationsBlock = returnedFromMixColumns;
        }
        private static void addRoundKey(List<List<byte>> operationsMatrix, List<List<byte>> roundKey)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    operationsMatrix[i][j] = (byte)(operationsMatrix[i][j] ^ roundKey[i][j]);
                }
            }
            operationsBlock = operationsMatrix;
        }
        private static void InverseShiftRows()
        {
            for (int i = 0; i < 4; i++)
            {
                if (i == 0)
                    continue;
                byte[] tmpRow = new byte[4];
                for(int j = 0; j < 4; j++)
                    tmpRow[j] = cipherBlock[i][j];
                for(int j = 0; j < 4; j++)
                    cipherBlock[i][j] = tmpRow[(j + (4 - i)) % 4];
            }
        }
        private static void AddRoundKey(int round)
        {
            for(int i = 0;i < 4;i++)
                for (int j = 0; j < 4; j++)
                    cipherBlock[i][j] = (byte)(cipherBlock[i][j] ^ keySchedInfo[round][i][j]);
        }
        private static void InverseSubBytes()
        {
            for(int i = 0; i < 4; i++)
                for(int j = 0; j < 4; j++)
                    cipherBlock[i][j] = SblockInverse[(cipherBlock[i][j] >> 4), (cipherBlock[i][j] & 0x0F)];
        }
        private static void InverseMixCols()
        {
            List<List<byte>> tmp = new List<List<byte>>();
            for (int i = 0; i < 4; i++)
                tmp.Add(new List<byte> { 0x00, 0x00, 0x00, 0x00 });
            for(int i = 0;i < 4;i++)
                for (int j = 0; j < 4; j++)
                    tmp[i][j] = cipherBlock[i][j];
            for(int i = 0;i < 4;i++)
            {
                cipherBlock[0][i] = (byte)(InverseMixColsMulti_E(tmp[0][i]) ^ InverseMixColsMulti_B(tmp[1][i])
                    ^ InverseMixColsMulti_D(tmp[2][i]) ^ InverseMixColsMulti_9(tmp[3][i]));
                cipherBlock[1][i] = (byte)(InverseMixColsMulti_9(tmp[0][i]) ^ InverseMixColsMulti_E(tmp[1][i])
                    ^ InverseMixColsMulti_B(tmp[2][i]) ^ InverseMixColsMulti_D(tmp[3][i]));
                cipherBlock[2][i] = (byte)(InverseMixColsMulti_D(tmp[0][i]) ^ InverseMixColsMulti_9(tmp[1][i])
                    ^ InverseMixColsMulti_E(tmp[2][i]) ^ InverseMixColsMulti_B(tmp[3][i]));
                cipherBlock[3][i] = (byte)(InverseMixColsMulti_B(tmp[0][i]) ^ InverseMixColsMulti_D(tmp[1][i])
                    ^ InverseMixColsMulti_9(tmp[2][i]) ^ InverseMixColsMulti_E(tmp[3][i]));
            }
        }
        private static byte InverseMixColsMulti_E(byte tmp)
        {
            return (byte)(InverseMixColsMulti_2(InverseMixColsMulti_2(InverseMixColsMulti_2(tmp)))
                            ^ InverseMixColsMulti_2(InverseMixColsMulti_2(tmp))
                            ^ InverseMixColsMulti_2(tmp));
        }
        private static byte InverseMixColsMulti_D(byte tmp)
        {
            return (byte)(InverseMixColsMulti_2(InverseMixColsMulti_2(InverseMixColsMulti_2(tmp)))
                            ^ InverseMixColsMulti_2(InverseMixColsMulti_2(tmp))
                            ^ tmp);
        }
        private static byte InverseMixColsMulti_B(byte tmp)
        {
            return (byte)(InverseMixColsMulti_2(InverseMixColsMulti_2(InverseMixColsMulti_2(tmp)))
                            ^ InverseMixColsMulti_2(tmp)
                            ^ tmp);
        }
        private static byte InverseMixColsMulti_9(byte tmp)
        {
            return (byte)(InverseMixColsMulti_2(InverseMixColsMulti_2(InverseMixColsMulti_2(tmp)))
                            ^ tmp);
        }
        private static byte InverseMixColsMulti_2(byte cipherCell)
        {
            if (cipherCell >> 7 == 0x01)
                return (byte)(cipherCell << 1);
            else
                return (byte)((cipherCell << 1) ^ (0x1B));
        }
        private static byte MixColsMulti_3(byte cipherCell)
        {
            return (byte)(cipherCell ^ MixColsMulti_2(cipherCell));
        }
        private static byte MixColsMulti_2(byte cipherCell)
        {
            if (cipherCell >> 7 == 0x01)
                return (byte)((cipherCell << 1) ^ (0x1B));
            else
                return (byte)(cipherCell << 1);
        }
    }
}
