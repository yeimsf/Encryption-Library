using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{
   public class InvalidAnlysisException : Exception
    {
        public InvalidAnlysisException() :
            base("Invalid Key.")
        {
        }
    }
}
