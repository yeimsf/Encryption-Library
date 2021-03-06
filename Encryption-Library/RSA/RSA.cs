using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{
    public static class RSA
    {
        public static int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();
            
            ulong n =(ulong)( p * q);
            uint m = (uint)(M);
            ulong calculated = 1;
            int counter = 0;
            int returnedE = Getsummations(e);
            while (counter<e)
            {
                counter += returnedE;
                if (counter > e)
                {
                    int difference = counter - e;
                    returnedE -= difference;
                }
                calculated *= poweringNumber(returnedE,m) % n;
                if (calculated>n)
                {
                    calculated = calculated % n;
                }
            }
            int C = (int)(calculated%n);
            return C;
        }

        public static int Decrypt(int p, int q, int C, int e)
        {
            //throw new NotImplementedException();
            ulong n = (ulong)(p * q);
            int omegaN = ((--p) * (--q));
            uint c = (uint)(C);
            int d = GetMultiplicativeInverse(e, omegaN);
            int returnedE = Getsummations(d);
            ulong calculated = 1;
            int counter = 0;
            while (counter < d)
            {
                counter += returnedE;
                if (counter > d)
                {
                    int difference = counter - d;
                    returnedE -= difference;
                }
                calculated *= poweringNumber(returnedE, c) % n;
                if (calculated>n)
                {
                    calculated = calculated % n;
                }
            }
            int M = (int)(calculated % n);
            
            return M;
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
        private static int Getsummations(int n)
        {
            double divide=999;
            while (divide>5)
            {
                divide = n / 2;
                Math.Floor(divide);
                n = (int)(divide);
            }
            return (int)(divide);
        }
        private static ulong poweringNumber(int raised,uint baseNumber)
        {
            ulong powerd = 1;
            for (int i = 0; i < raised; i++)
            {
                powerd *= baseNumber;
            }
            return (ulong)(powerd);
        }
    }
}
