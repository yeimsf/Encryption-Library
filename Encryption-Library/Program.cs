using System;
using System.Collections.Generic;
using System.Collections;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_Library
{
    class Program
    {
        Dictionary<int, string> Techniques = new Dictionary<int, string>() 
        { 
            { 1, "Caeser" }, { 2, "Rail Fence" }, 
            { 3, "Hill Cipher" }, { 4, "Columnar" }, 
            { 5, "Monoalphabetic" }, { 6, "Play Fair" },
            { 7, "Vigenere" }, { 8, "RC4" }, 
            { 9, "DES" }, { 10, "Triple DES" },
            { 11, "AES" }, { 12, "RSA" },
            { 13, "Diffie Hellman" }, { 14, "EL-GAMAL" },
        };
        static void Main(string[] args)
        {
            bool ExitStatus = false;
            while (true)
            {
                Console.Clear();
                Console.WriteLine("--------------------------------------------------------------------");
                Console.WriteLine("--------------------Avalanche Encryption Library--------------------");
                Console.WriteLine("-----------------Choose Encryption Algorithm Desired----------------");
                Console.WriteLine("1. Caeser");
                Console.WriteLine("2. Rail Fence");
                Console.WriteLine("3. Hill Cipher");
                Console.WriteLine("4. Columnar");
                Console.WriteLine("5. Monoalphabetic");
                Console.WriteLine("6. Play Fair");
                Console.WriteLine("7. Vigenere");
                Console.WriteLine("8. RC4");
                Console.WriteLine("9. DES");
                Console.WriteLine("10. Triple DES");
                Console.WriteLine("11. AES");
                Console.WriteLine("12. RSA");
                Console.WriteLine("13. Diffie Hellman");
                Console.WriteLine("14. EL-GAMAL");
                Console.WriteLine("0. EXIT INTERFACE");
                Console.WriteLine("--------------------------------------------------------------------");
                Console.WriteLine("Enter Desired Technique>>>");
                int choice = int.Parse(Console.ReadLine());
                switch (choice)
                {
                    case 0:
                        ExitStatus = true;
                        break;
                    case 1:
                        Handler(1);
                        break;
                    case 2:
                        Handler(2);
                        break;
                    case 3:
                        Handler(3);
                        break;
                    case 4:
                        Handler(4);
                        break;
                    case 5:
                        Handler(5);
                        break;
                    case 6:
                        Handler(6);
                        break;
                    case 7:
                        Handler(7);
                        break;
                    case 8:
                        Handler(8);
                        break;
                    case 9:
                        Handler(9);
                        break;
                    case 10:
                        Handler(10);
                        break;
                    case 11:
                        Handler(11);
                        break;
                    case 12:
                        Handler(12);
                        break;
                    case 13:
                        Handler(13);
                        break;
                    case 14:
                        Handler(14);
                        break;
                    default:
                        Console.WriteLine("Invalid Input!");
                        break;
                }
                if (ExitStatus)
                    break;
            }

        }
        private static void Handler(int TechniqueNumber)
        {
            bool ExitStatus = false;
            while (true)
            {
                Console.Clear();
                Console.WriteLine("--------------------------------------------------------------------");
                Console.WriteLine("--------------------Avalanche Encryption Library--------------------");
                Console.WriteLine("1. Encrypt");
                Console.WriteLine("2. Decrypt");
                if (TechniqueNumber != 6 && TechniqueNumber != 8 && TechniqueNumber != 14 && TechniqueNumber != 13 && TechniqueNumber != 11 && TechniqueNumber != 12)
                    Console.WriteLine("3. Analyze");
                Console.WriteLine("0. Return To Main Menu");
                Console.WriteLine("--------------------------------------------------------------------");
                Console.WriteLine("Enter Desired Operation>>>");
                int choice = int.Parse(Console.ReadLine());
                if (choice == 0)
                    ExitStatus = true;
                else if (choice == 1)
                    Encryption_Handler(TechniqueNumber);
                else if(choice == 2)
                    Decryption_Handler(TechniqueNumber);
                else if (choice == 3)
                    Analysis_Handler(TechniqueNumber);
                if (ExitStatus)
                    break;
            }
        }
        private static void Encryption_Handler(int TechniqueNumber)
        {

        }
        private static void Decryption_Handler(int TechniqueNumber)
        {

        }
        private static void Analysis_Handler(int TechniqueNumber)
        {

        }
    }
}
