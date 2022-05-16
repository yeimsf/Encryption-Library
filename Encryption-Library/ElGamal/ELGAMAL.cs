using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{
    public static class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public static List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            //throw new NotImplementedException();
            List<long> resaults = new List<long>();
            ulong newQ = (ulong)(q);
            int c1 = 0,K=0,c2=0;
            poweringNumber(k, alpha, ref c1, newQ);
            poweringNumber(k, y, ref K, newQ);
            c2 = (K * m) % q;
            resaults.Add((long)c1);
            resaults.Add((long)c2);
            return resaults;
        }
        public static int Decrypt(int c1, int c2, int x, int q)
        {
            //throw new NotImplementedException();
            ulong newQ = (ulong)(q);
            int k = 0;
            poweringNumber(x, c1, ref k, newQ);
            int Kinverse=GetMultiplicativeInverse(k, q);
            return (c2 * Kinverse) % q;
        }
        private static void poweringNumber(int raised, int baseNumber, ref int resault, ulong q)
        {
            ulong BN = (ulong)(baseNumber);
            ulong powerd = 1;
            for (int i = 0; i < raised; i++)
            {
                powerd *= BN;
                if (powerd > q)
                {
                    powerd = powerd % q;
                }
            }
            resault = (int)powerd;
        }
        private static int GetMultiplicativeInverse(int number, int baseN)
        {
            List<int> Q = new List<int>(), A1 = new List<int>()
                , A2 = new List<int>(), A3 = new List<int>()
                , B1 = new List<int>(), B2 = new List<int>()
                , B3 = new List<int>();

            int inverse = 0;
            int counter = 0;
            bool noInv = false;
            while (true)
            {
                if (counter == 0)
                {
                    A1.Add(1);
                    A2.Add(0);
                    B1.Add(0);
                    B2.Add(1);
                    Q.Add(0);
                    A3.Add(baseN);
                    B3.Add(number);
                }
                else
                {
                    Q.Add(A3[counter - 1] / B3[counter - 1]);
                    A3.Add(B3[counter - 1]);
                    B3.Add(A3[counter - 1] - Q[counter] * B3[counter - 1]);
                    A1.Add(B1[counter - 1]);
                    A2.Add(B2[counter - 1]);
                    B1.Add(A1[counter - 1] - Q[counter] * B1[counter - 1]);
                    B2.Add(A2[counter - 1] - Q[counter] * B2[counter - 1]);
                }
                if (B3[counter] == 1)
                {
                    inverse = B2[counter];
                    break;
                }
                else if (B3[counter] == 0)
                {
                    inverse = -1;
                    noInv = true;
                    break;
                }
                else if (B3[counter] < 0)
                    break;
                counter++;
            }
            if (inverse < 0 && noInv)
                return inverse;
            else if (inverse < 0 && !noInv)
                return inverse + baseN;
            else
                return inverse;
        }
    }
}
