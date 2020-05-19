using System;

namespace Sodium.Exceptions
{
    public class InvalidSodiumPasswordString : Exception
    {
        public InvalidSodiumPasswordString()
          : base("Invalid Password string for SCrypt")
        {
        }
    }
}