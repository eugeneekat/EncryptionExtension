using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Encryptors
{
    //Main Generic Class
    public abstract class Encryptor<TRet, TSoure, TCode>
    {
        abstract public TRet Encrypt(TSoure source, TCode code);
        abstract public TRet Decrypt(TSoure source, TCode code);
    }

    //Byte Classes Factory
    public abstract class ByteEncryptor : Encryptor<byte[], byte[], byte[]>
    {
        public static XorEncryptor Xor
        {
            get { return new XorEncryptor(); }
        }

        //Ref encrypt decrypt
        public abstract void Encrypt(ref byte[] source, byte[] code);
        public abstract void Decrypt(ref byte[] source, byte[] code);

        //Async methods with cancellation
        public abstract int Encrypt(byte[] source, byte[] code, CancellationToken token);
        public abstract int Decrypt(byte[] source, byte[] code, CancellationToken token);
    }

    //Text Classes Factory
    public abstract class TextEncryptor : Encryptor<string, string, string>
    {
        public static CeasarEncryptor Ceasar { get { return new CeasarEncryptor(); } }
    }

    //Xor byte[] Encrypt(byte[] source, byte[] code)
    public class XorEncryptor : ByteEncryptor
    {
        //Create new encrypted/decrypted byte array
        public override byte[] Encrypt(byte[] source, byte[] code)
        {
            byte[] result = new byte[source.Length];
            for (int i = 0, j = 0; i < source.Length; i++, j++)
            {
                if (j == code.Length)
                    j = 0;
                result[i] = (byte)(source[i] ^ code[j]);
            }
            return result;
        }
        public override byte[] Decrypt(byte[] source, byte[] code)
        {
            return this.Encrypt(source, code);
        }
        //Encrypt/Decrypt source by ref
        public override void Encrypt(ref byte[] source, byte[] code)
        {
            for (int i = 0, j = 0; i < source.Length; i++, j++)
            {
                if (j == code.Length)
                    j = 0;
                source[i] = (byte)(source[i] ^ code[j]);
            }
        }
        public override void Decrypt(ref byte[] source, byte[] code)
        {
            this.Encrypt(ref source, code);
        }



        //With Cancellation
        public override int Encrypt(byte[] source, byte[] code, CancellationToken token)
        {
            for (int i = 0, j = 0; i < source.Length; i++, j++)
            {
                if (token.IsCancellationRequested)
                    //If cancelled - throw exception
                    token.ThrowIfCancellationRequested();
                if (j == code.Length)
                    j = 0;
                source[i] = (byte)(source[i] ^ code[j]);
            }
            //Return successful result
            return source.Length;
        }
        public override int Decrypt(byte[] source, byte[] code, CancellationToken token)
        {
            return this.Encrypt(source, code, token);
        }
    }
    
    //Ceasar TextEncryptor
    public class CeasarEncryptor : TextEncryptor
    {
        //TextEncryptor main method string Encrypt/Decrypt(string, string)
        public override string Encrypt(string source, string code)
        {
            return this.Encrypt(source, int.Parse(code));
        }
        public override string Decrypt(string source, string code)
        {
            return this.Decrypt(source, int.Parse(code));
        }
        //CeasarEncryptor overload string Encrypt/Decrypt(string, int)
        public string Encrypt(string source, int code)
        {
            StringBuilder sb = new StringBuilder(source.Length);
            for (int i = 0; i < source.Length; i++)
                sb.Append((char)(source[i] + code));
            return sb.ToString();
        }
        public string Decrypt(string source, int code)
        {
            StringBuilder sb = new StringBuilder(source.Length);
            for (int i = 0; i < source.Length; i++)
                sb.Append((char)(source[i] - code));
            return sb.ToString();
        }
    }
}
