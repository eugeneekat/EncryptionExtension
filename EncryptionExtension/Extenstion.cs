using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Encryptors;
using System.IO;
using System.Threading;
using System.Security.Cryptography;

namespace EncryptionExtension
{
    public static class Extenstion
    {
        static byte[] mark = Encoding.Unicode.GetBytes("Crypt");

        //Base ByteEncryptor methods for Stream
        public static void Encrypt(this Stream stream, ByteEncryptor enc, byte[] key)
        {
            if (stream == null || enc == null || key == null)
                throw new ArgumentNullException("Null argument");
            //Если файл пустой или ключ пустой бросает исключение
            if (stream.Length == 0)
                throw new ArgumentException("Stream is empty", "stream");
            if (key.Length == 0)
                throw new ArgumentException("Key is empty", "key");

            if (stream.Length > mark.Length)
                stream.Position = stream.Length - mark.Length;
            byte[] compareMark = new byte[mark.Length];
            stream.Read(compareMark, 0, mark.Length);
            //Если метки нету значит файл не шифрован ещё
            if (!mark.SequenceEqual(compareMark))
            {
                //Устанавливаю позицию в начало создаю буфер и считываю содержимое
                stream.Position = 0;
                byte[] buf = new byte[stream.Length];
                stream.Read(buf, 0, buf.Length);

                //Зашфировать используя шифровщик и записать
                enc.Encrypt(ref buf, key);
                stream.Position = 0;
                stream.Write(buf, 0, buf.Length);

                //Записать хеш
                MD5 md5 = MD5.Create();
                byte[] bHash = md5.ComputeHash(key);
                stream.Write(bHash, 0, bHash.Length);

                //Записать метку            
                stream.Write(mark, 0, mark.Length);
            }
            stream.Position = 0;
        }
        public static void Decrypt(this Stream stream, ByteEncryptor enc, byte[] key)
        {
            if (stream == null || enc == null || key == null)
                throw new ArgumentNullException("Null argument");
            //Если файл пустой или ключ пустой бросает исключение
            if (stream.Length == 0)
                throw new ArgumentException("Stream is empty", "stream");
            if (key.Length == 0)
                throw new ArgumentException("Key is empty", "key");

            //Создаем метку и метку для сравнивания
            stream.Position = 0;
            byte[] compareMark = new byte[mark.Length];
            stream.Position = stream.Length - mark.Length;
            stream.Read(compareMark, 0, compareMark.Length);

            //Если есть метка
            if (mark.SequenceEqual(compareMark))
            {
                //Создаем хеш и сравниваем
                MD5 md5 = MD5.Create();
                byte[] bHash = md5.ComputeHash(key);
                byte[] compareHash = new byte[bHash.Length];
                stream.Position = stream.Length - mark.Length - bHash.Length;
                stream.Read(compareHash, 0, bHash.Length);
                //Если хеш совпадает
                if (bHash.SequenceEqual(compareHash))
                {
                    //Создаем буфер считываем в него данные
                    byte[] buf = new byte[stream.Length];
                    stream.Position = 0;
                    stream.Read(buf, 0, buf.Length);
                    //Расшифровываем
                    enc.Decrypt(ref buf, key);
                    //Записывем
                    stream.Position = 0;
                    stream.Write(buf, 0, buf.Length);
                    //Урезаем метку и хеш
                    stream.Position = 0;
                    stream.SetLength(buf.Length - mark.Length - bHash.Length);
                }
                else
                    throw new ArgumentException("Incorrect key.", "key");
            }
            stream.Position = 0;
        }

        //Base TextEncryptor methods for string
        public static string Encrypt(this string source, TextEncryptor enc, string code)
        {
            return enc.Encrypt(source, code);
        }
        public static string Decrypt(this string source, TextEncryptor enc, string code)
        {
            return enc.Decrypt(source, code);
        }

        //Ceasar overloaded methods for string
        public static string Encrypt(this string source, CeasarEncryptor enc, int code)
        {
            return enc.Encrypt(source, code);
        }
        public static string Decrypt(this string source, CeasarEncryptor enc, int code)
        {
            return enc.Decrypt(source, code);
        }

        //Base ByteEncryptor methods for Stream async
        public static async Task EncryptAsync(this Stream stream, ByteEncryptor enc, byte[] key)
        {
            if (stream == null || enc == null || key == null)
                throw new ArgumentNullException("Null argument");
            //Если файл пустой или ключ пустой бросает исключение
            if (stream.Length == 0)
                throw new ArgumentException("Stream is empty", "stream");
            if (key.Length == 0)
                throw new ArgumentException("Key is empty", "key");

            //Проверка метки
            if (stream.Length > mark.Length)
                stream.Position = stream.Length - mark.Length;
            byte[] compareMark = new byte[mark.Length];
            await stream.ReadAsync(compareMark, 0, mark.Length);
            //Если метки нету значит файл не шифрован ещё
            if (!mark.SequenceEqual(compareMark))
            {
                //Устанавливаю позицию в начало создаю буфер и считываю содержимое
                stream.Position = 0;
                byte[] buf = new byte[stream.Length];
                await stream.ReadAsync(buf, 0, buf.Length);

                //Зашфировать используя шифровщик и записать
                await Task.Run(() => enc.Encrypt(ref buf, key));

                stream.Position = 0;
                await stream.WriteAsync(buf, 0, buf.Length);

                //Записать хеш
                MD5 md5 = MD5.Create();
                byte[] bHash = md5.ComputeHash(key);
                await stream.WriteAsync(bHash, 0, bHash.Length);

                //Записать метку            
                await stream.WriteAsync(mark, 0, mark.Length);
            }
            stream.Position = 0;
        }
        public static async Task DecryptAsync(this Stream stream, ByteEncryptor enc, byte[] key)
        {
            if (stream == null || enc == null || key == null)
                throw new ArgumentNullException("Null argument");
            //Если файл пустой или ключ пустой бросает исключение
            if (stream.Length == 0)
                throw new ArgumentException("Stream is empty", "stream");
            if (key.Length == 0)
                throw new ArgumentException("Key is empty", "key");

            //Создаем метку и метку для сравнивания
            stream.Position = 0;
            byte[] compareMark = new byte[mark.Length];
            stream.Position = stream.Length - mark.Length;
            await stream.ReadAsync(compareMark, 0, compareMark.Length);

            //Если есть метка
            if (mark.SequenceEqual(compareMark))
            {
                //Создаем хеш и сравниваем
                MD5 md5 = MD5.Create();
                byte[] bHash = md5.ComputeHash(key);
                byte[] compareHash = new byte[bHash.Length];
                stream.Position = stream.Length - mark.Length - bHash.Length;
                await stream.ReadAsync(compareHash, 0, bHash.Length);
                //Если хеш совпадает
                if (bHash.SequenceEqual(compareHash))
                {
                    //Создаем буфер считываем в него данные
                    byte[] buf = new byte[stream.Length];
                    stream.Position = 0;
                    await stream.ReadAsync(buf, 0, buf.Length);
                    //Расшифровываем
                    await Task.Run(() => enc.Decrypt(ref buf, key));
                    //Записывем
                    stream.Position = 0;
                    await stream.WriteAsync(buf, 0, buf.Length);
                    //Урезаем метку и хеш
                    stream.Position = 0;
                    stream.SetLength(buf.Length - mark.Length - bHash.Length);
                }
                else
                    throw new ArgumentException("Incorrect key.", "key");
            }
            stream.Position = 0;
        }

        //Base ByteEncryptor methods for Stream async with cancellation token
        public static async Task EncryptAsync(this Stream stream, ByteEncryptor enc, byte[] key, CancellationToken token)
        {
            if (stream == null || enc == null || key == null)
                throw new ArgumentNullException("Null argument");
            //Если файл пустой или ключ пустой бросает исключение
            if (stream.Length == 0)
                throw new ArgumentException("Stream is empty", "stream");
            if (key.Length == 0)
                throw new ArgumentException("Key is empty", "key");

            //Проверка метки
            if (stream.Length > mark.Length)
                stream.Position = stream.Length - mark.Length;
            byte[] compareMark = new byte[mark.Length];
            await stream.ReadAsync(compareMark, 0, mark.Length, token);
            //Если метки нету значит файл не шифрован ещё
            if (!mark.SequenceEqual(compareMark))
            {
                //Устанавливаю позицию в начало создаю буфер и считываю содержимое
                stream.Position = 0;
                byte[] buf = new byte[stream.Length];
                await stream.ReadAsync(buf, 0, buf.Length, token);

                //Зашфировать используя шифровщик и записать
                await enc.EncryptAsync(buf, key, token);

                stream.Position = 0;
                await stream.WriteAsync(buf, 0, buf.Length, token);

                //Записать хеш
                MD5 md5 = MD5.Create();
                byte[] bHash = md5.ComputeHash(key);
                await stream.WriteAsync(bHash, 0, bHash.Length, token);

                //Записать метку            
                await stream.WriteAsync(mark, 0, mark.Length, token);
            }
            stream.Position = 0;
        }
        public static async Task DecryptAsync(this Stream stream, ByteEncryptor enc, byte[] key, CancellationToken token)
        {
            if (stream == null || enc == null || key == null)
                throw new ArgumentNullException("Null argument");
            //Если файл пустой или ключ пустой бросает исключение
            if (stream.Length == 0)
                throw new ArgumentException("Stream is empty", "stream");
            if (key.Length == 0)
                throw new ArgumentException("Key is empty", "key");

            //Создаем метку и метку для сравнивания
            stream.Position = 0;
            byte[] compareMark = new byte[mark.Length];
            stream.Position = stream.Length - mark.Length;
            await stream.ReadAsync(compareMark, 0, compareMark.Length, token);

            //Если есть метка
            if (mark.SequenceEqual(compareMark))
            {
                //Создаем хеш и сравниваем
                MD5 md5 = MD5.Create();
                byte[] bHash = md5.ComputeHash(key);
                byte[] compareHash = new byte[bHash.Length];
                stream.Position = stream.Length - mark.Length - bHash.Length;
                await stream.ReadAsync(compareHash, 0, bHash.Length, token);
                //Если хеш совпадает
                if (bHash.SequenceEqual(compareHash))
                {
                    //Создаем буфер считываем в него данные
                    byte[] buf = new byte[stream.Length];
                    stream.Position = 0;
                    await stream.ReadAsync(buf, 0, buf.Length, token);
                    //Расшифровываем
                    await enc.DecryptAsync(buf, key, token);
                    //Записывем
                    stream.Position = 0;
                    await stream.WriteAsync(buf, 0, buf.Length, token);
                    //Урезаем метку и хеш
                    stream.Position = 0;
                    stream.SetLength(buf.Length - mark.Length - bHash.Length);
                }
                else
                    throw new ArgumentException("Incorrect key.", "key");
            }
            stream.Position = 0;
        }
    }
}
