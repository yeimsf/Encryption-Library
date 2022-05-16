using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{
    public static class DiffieHellman 
    {
        public static List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            int Ya=0, Yb=0, Ka=0, Kb=0;
            ulong newQ = (ulong)(q);
            List<int> keys = new List<int>();
            poweringNumber(xa, alpha,ref Ya,newQ);
            poweringNumber(xb, alpha,ref Yb,newQ);
            poweringNumber(xb, Ya,ref Kb,newQ);
            poweringNumber(xa, Yb,ref Ka,newQ);
            keys.Add(Ka);
            keys.Add(Kb);
            return keys;
        }
        private static void poweringNumber(int raised, int baseNumber,ref int resault,ulong q)
        {
            ulong BN = (ulong)(baseNumber);
            ulong powerd = 1;
            for (int i = 0; i < raised; i++)
            {
                powerd *= BN;
                if (powerd>q)
                {
                    powerd = powerd % q;
                }
            }
            resault = (int)powerd;
        }
    }
}
