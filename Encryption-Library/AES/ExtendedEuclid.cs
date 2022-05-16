using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{
    public static class ExtendedEuclid 
    {
        public static int GetMultiplicativeInverse(int number, int baseN)
        {
            List<int> Q = new List<int>(), A1 = new List<int>()
                , A2 = new List<int>(), A3 = new List<int>()
                , B1 = new List<int>(), B2 = new List<int>()
                , B3 = new List<int>();

            int inverse = 0;
            int counter = 0;
            bool noInv = false;
            while(true)
            {
                if(counter == 0)
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
