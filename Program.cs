using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Mimi_Verify
{
    unsafe class Program
    {
        private const string base_characters = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
        private static Dictionary<char, int> base_conversion = null;
        private static readonly BigInteger base_int = new BigInteger(base_characters.Length);

        //private static readonly ECCurve curve = ECCurve.CreateFromFriendlyName("curve25519");
        private static readonly ECCurve curve = ECCurve.NamedCurves.nistP256;
        private static readonly Encoding encoding = Encoding.Default;
        private static readonly HashAlgorithmName hash_algorithm = HashAlgorithmName.SHA512;

        private static delegate*<int> execution_mode = &Prompt;
        private static Stream output = Console.OpenStandardOutput();
        private static bool file_output = false;
        private static bool raw_output = false;

        private static byte[] hash = null;
        private static byte[] signature = null;
        private static byte[] key = null;

        static int Challenge()
        {
            while (key == null)
                TryReadOrParse(ReceiveUserInput("Public Key: "), out key);

            using (var alg = HashAlgorithm.Create(hash_algorithm.Name))
                RandomNumberGenerator.Fill(hash = new byte[alg.HashSize / 8]);

            Console.WriteLine("To complete the challenge, have the person you're challenging sign the challenge (Mimi-Verify.exe -sign -key <private key> -data <challenge>)");
            Console.WriteLine();
            Console.Write("Challenge: ");
            Console.WriteLine(ToBaseCharacters(hash));

            while (signature == null)
                TryReadOrParse(ReceiveUserInput("Response: "), out signature);

            using ECDsa dsa = DSAFromPublicKey();

            if (dsa.VerifyHash(hash, signature))
                Console.WriteLine("Pass!");
            else
                Console.WriteLine("Fail!");

            return 0;
        }

        static ECDsa DSAFromPrivateKey()
            => ECDsa.Create(new ECParameters()
            {
                Curve = curve,
                D = key
            });

        static ECDsa DSAFromPublicKey()
            => ECDsa.Create(new ECParameters()
            {
                Curve = curve,
                Q = new ECPoint()
                {
                    X = key.AsSpan().Slice(0, key.Length / 2).ToArray(),
                    Y = key.AsSpan().Slice(key.Length / 2).ToArray()
                }
            });

        static int GetBaseCharacterValue(char c)
        {
            if (base_conversion == null)
            {
                base_conversion = new Dictionary<char, int>();
                for (int i = 0; i < base_characters.Length; i++)
                    base_conversion.Add(base_characters[i], i);
            }

            return base_conversion[c];
        }

        static int Help()
        {
            Console.WriteLine("Mimi-Verify.exe [args]");
            Console.WriteLine();
            Console.WriteLine("-challenge                      \tGenerates a random hash, then prompts for a signed version of it, then checks against it using the specified public key");
            Console.WriteLine("-data <file_or_base56_data>     \tSpecifies a file or hash, if it's a file it will be hashed");
            Console.WriteLine("-key <file_or_base56_data>      \tSpecifies a private or public key written in base56, or stored in a file");
            Console.WriteLine("-new                            \tCreates a new key pair, no other options will be considered");
            Console.WriteLine("-out <file>                     \tSpecifies an output file to write the output of commands to");
            Console.WriteLine("-process                        \tDumps whatever it reads to output");
            Console.WriteLine("-raw                            \tSpecifies that output does not need to be human-readable. Good for storing keys and signatures.");
            Console.WriteLine("-sign                           \tSpecifies that we're going to sign the input data (see -data)");
            Console.WriteLine("-signature <file_or_base56_data>\tSpecifies a signature we're going to read");
            Console.WriteLine("-verify                         \tSpecifies we're going to verify a signature against the data and key (public)");

            return 0;
        }

        static int Main(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
                ReadArg(args, ref i);

            int ret;
            if (execution_mode != null)
                ret = execution_mode();
            else
                ret = 1;

            output.Flush();
            output.Close();

            return ret;
        }

        static int NewKey()
        {
            ECParameters parameters;
            using (ECDsa dsa_gen = ECDsa.Create(curve))
                parameters = dsa_gen.ExportExplicitParameters(true);

            if (!raw_output)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append("Private Key: ");
                builder.AppendLine(ToBaseCharacters(parameters.D));

                ECPoint point = parameters.Q;
                byte[] public_key = new byte[point.X.Length + point.Y.Length];
                Array.Copy(point.X, 0, public_key, 0, point.X.Length);
                Array.Copy(point.Y, 0, public_key, point.X.Length, point.Y.Length);

                builder.Append("Public Key: ");
                builder.AppendLine(ToBaseCharacters(public_key));

                output.Write(encoding.GetBytes(builder.ToString()));
            }
            else
                output.Write(parameters.D);

            return 0;
        }

        static int ProcessData()
        {
            byte[] data = key ?? signature ?? hash;

            while (data == null)
                TryReadOrParse(ReceiveUserInput("Key/Hash/Signature/File: "), out data);

            if (raw_output)
                output.Write(data);
            else
                output.Write(encoding.GetBytes(ToBaseCharacters(data) + Environment.NewLine));

            return 0;
        }

        static int Prompt()
        {
            Console.WriteLine("Challenge - Create a hash for someone else to sign, then verify the signature they provide.");
            Console.WriteLine("New Key   - Generate a Keypair, you must keep the private key secret, post the public key wherever.");
            Console.WriteLine("Process   - Read data in, and dump it to the console or to a file in raw format (Useful for storing keys and signatures in files, or extracting them)");
            Console.WriteLine("Sign      - Sign data, this allows people to verify that a file hasn't been tampered with since you had it last, in addition to verifying the file is from you.");
            Console.WriteLine("Verify    - Verify a signature, this checks whether a signature matches a file or hash, and that it came from the person you think it came from.");
            Console.WriteLine();
            Console.Write("Challenge, New Key, Process, Sign, or Verify? [C,N,P,S,V] ");
            int ret = -1;
            while(ret == -1)
            {
                switch(Console.ReadKey(true).Key)
                {
                    case ConsoleKey.C:
                        Console.WriteLine("C");
                        ret = Challenge();
                        break;

                    case ConsoleKey.N:
                        Console.WriteLine("N");
                        ret = NewKey();
                        break;

                    case ConsoleKey.P:
                        Console.WriteLine("P");
                        PromptConfig();
                        ret = ProcessData();
                        break;

                    case ConsoleKey.S:
                        Console.WriteLine("S");
                        ret = Sign();
                        break;

                    case ConsoleKey.V:
                        Console.WriteLine("V");
                        ret = Verify();
                        break;

                    default:
                        Console.Beep();
                        break;
                }
            }

            if (!file_output)
                while (Console.ReadKey(true).Key != ConsoleKey.Enter)
                    continue;

            return ret;
        }

        static void PromptConfig()
        {
            Console.Write("Output to File? [Y/N] ");
            while (true)
            {
                switch (Console.ReadKey(true).Key)
                {
                    case ConsoleKey.N:
                        Console.WriteLine("N");
                        return; ;

                    case ConsoleKey.Y:
                        Console.WriteLine("Y");
                        SetOutput(ReceiveUserInput("Output File: "));
                        raw_output = true;
                        return;

                    default:
                        Console.Beep();
                        break;
                }
            }
        }

        static string ReceiveUserInput(string prompt)
        {
            Console.Write(prompt);
            return Console.ReadLine();
        }

        private static void ReadArg(string[] args, ref int i)
        {
            switch(args[i].ToLower())
            {
                case "-challenge":
                    execution_mode = &Challenge;
                    break;

                case "-data":
                    if (HasNext(args, i) && TryHashOrParse(args[i + 1], out hash))
                        i++;
                    else
                        Error(args, out i, "Must specify a valid hash or file!");
                    break;

                case "-help":
                    execution_mode = &Help;
                    break;

                case "-key":
                    if (HasNext(args, i) && TryReadOrParse(args[i + 1], out key))
                        i++;
                    else
                        Error(args, out i, "Must specify a valid key or keyfile!");
                    break;

                case "-new":
                    execution_mode = &NewKey;
                    break;

                case "-out":
                    if (HasNext(args, i))
                        SetOutput(args[++i]);
                    else
                        Error(args, out i, "Must provide an output file!");
                    break;

                case "-process":
                    execution_mode = &ProcessData;
                    break;

                case "-raw":
                    raw_output = true;
                    break;

                case "-sign":
                    execution_mode = &Sign;
                    break;

                case "-signature":
                    if (HasNext(args, i) && TryReadOrParse(args[i + 1], out signature))
                        i++;
                    else
                        Error(args, out i, "Must specify a valid signature or file!");
                    break;

                case "-verify":
                    execution_mode = &Verify;
                    break;
            }

            static void Error(string[] args, out int i, string message)
            {
                execution_mode = null;
                i = args.Length;
                Console.WriteLine(message);
            }

            static bool HasNext(string[] args, int i)
                => i + 1 < args.Length;
        }

        static void SetOutput(string dest)
        {
            output.Close();
            output = File.Open(dest, FileMode.Append, FileAccess.Write);
            file_output = true;
        }

        static int Sign()
        {
            while(key == null)
                TryReadOrParse(ReceiveUserInput("Private Key: "), out key);

            while (hash == null)
                TryHashOrParse(ReceiveUserInput("Hash or File: "), out hash);

            using ECDsa dsa = DSAFromPrivateKey();
            signature = dsa.SignHash(hash);

            if (!raw_output)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append("Signature: ");
                builder.AppendLine(ToBaseCharacters(signature));
                output.Write(encoding.GetBytes(builder.ToString()));
            }
            else
                output.Write(signature);

            return 0;
        }

        static string ToBaseCharacters(byte[] data)
        {
            BigInteger value = new BigInteger(data, true, true);

            int characters = (int)BigInteger.Log(BigInteger.Pow(byte.MaxValue + 1, data.Length), base_characters.Length) + 1;
            char* ptr = stackalloc char[characters];

            BigInteger divisor = BigInteger.Pow(base_int, characters);
            for (int i = 0; i < characters; i++)
            {
                divisor /= base_int;
                ptr[i] = base_characters[(int)((value / divisor) % base_int)];
            }

            return new string(ptr, 0, characters);
        }

        static bool TryHashOrParse(string data, out byte[] hashed_or_parsed_data)
        {
            if (File.Exists(data))
            {
                int read = -1;
                Span<byte> buffer = stackalloc byte[512];
                using (FileStream stream = File.OpenRead(data))
                using (IncrementalHash hash = IncrementalHash.CreateHash(hash_algorithm))
                {
                    while (read != 0)
                    {
                        read = stream.Read(buffer);
                        hash.AppendData(buffer.Slice(0, read));
                    }

                    hashed_or_parsed_data = hash.GetCurrentHash();
                }

                return true;
            }

            return TryParse(data, out hashed_or_parsed_data);
        }

        static bool TryParse(string data, out byte[] parsed_data)
        {
            if (base_conversion == null)
            {
                base_conversion = new Dictionary<char, int>();
                for (int i = 0; i < base_characters.Length; i++)
                    base_conversion[base_characters[i]] = i;
            }
            
            BigInteger value = BigInteger.Zero;
            for (int i = 0; i < data.Length; i++)
            {
                if (!base_conversion.TryGetValue(data[i], out int converted))
                {
                    parsed_data = null;
                    return false;
                }

                value *= base_int;
                value += converted;
            }

            parsed_data = new byte[(int)BigInteger.Log(BigInteger.Pow(base_int, data.Length), byte.MaxValue + 1)];
            value.TryWriteBytes(parsed_data.AsSpan().Slice(parsed_data.Length - value.GetByteCount(true)), out _, true, true);
            return true;
        }

        static bool TryReadOrParse(string data, out byte[] read_or_parsed_data)
        {
            if (File.Exists(data))
            {
                read_or_parsed_data = File.ReadAllBytes(data);
                return true;
            }

            return TryParse(data, out read_or_parsed_data);
        }

        static int Verify()
        {
            while (key == null)
                TryReadOrParse(ReceiveUserInput("Public Key: "), out key);

            while (hash == null)
                TryHashOrParse(ReceiveUserInput("Hash or File: "), out hash);

            while (signature == null)
                TryReadOrParse(ReceiveUserInput("Signature: "), out signature);

            using ECDsa dsa = DSAFromPublicKey();

            if (dsa.VerifyHash(hash, signature))
            {
                output.Write(encoding.GetBytes($"Signature Verified!{Environment.NewLine}"));
                return 0;
            }

            output.Write(encoding.GetBytes($"Signature Failed!{Environment.NewLine}"));
            return 1;
        }
    }
}
