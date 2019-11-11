using System;
using System.Security.Cryptography;
using Cerberix.Serialization;
using Cerberix.Extension;
using System.Collections.Generic;
using System.IO;

namespace Cerberix.Crypto.DotNet
{
    public static class Factory
    {
        /// <summary>
        ///     AES 256 Plus HMAC
        /// </summary>
        public static class AES256PlusHMACPump
        {
            public static ICryptDecryptProvider NewInstance(
                IBase64Converter base64Converter,
                IByteConverter byteConverter,
                string cryptKeyValue,
                string hmacSaltValue
                )
            {
                return new AES256PlusHMACCryptDecryptProvider(
                    base64Converter: base64Converter,
                    byteConverter: byteConverter,
                    cryptKeyValue: cryptKeyValue,
                    hmacSaltValue: hmacSaltValue
                    );
            }

            private class AES256PlusHMACCryptDecryptProvider : ICryptProvider, ICryptDecryptProvider
            {
                private readonly int BlockBitSize = 128;
                private readonly int KeyBitSize = 256;

                private readonly IBase64Converter Base64Converter;
                private readonly IByteConverter ByteConverter;

                private readonly string CryptKeyValue;
                private readonly string HmacSaltValue;

                public AES256PlusHMACCryptDecryptProvider(
                    IBase64Converter base64Converter,
                    IByteConverter byteConverter,
                    string cryptKeyValue,
                    string hmacSaltValue
                    )
                {
                    if (base64Converter == null)
                    {
                        throw new ArgumentNullException("base64Converter");
                    }
                    if (byteConverter == null)
                    {
                        throw new ArgumentNullException("byteConverter");
                    }
                    if (cryptKeyValue == null)
                    {
                        throw new ArgumentNullException("cryptKeyValue");
                    }
                    if (cryptKeyValue.Length != 32)
                    {
                        throw new ArgumentException(paramName: "cryptKeyValue", message: "cryptKeyValue must represent a 256-bit value.");
                    }
                    if (hmacSaltValue == null)
                    {
                        throw new ArgumentNullException("hmacSaltValue");
                    }
                    if (hmacSaltValue.Length != 32)
                    {
                        throw new ArgumentException(paramName: "hmacSaltValue", message: "hmacSaltValue must represent a 256-bit value.");
                    }

                    Base64Converter = base64Converter;
                    ByteConverter = byteConverter;

                    CryptKeyValue = cryptKeyValue;
                    HmacSaltValue = hmacSaltValue;
                }

                public string Crypt(string clearText)
                {
                    if (clearText == null)
                    {
                        throw new ArgumentNullException("clearText");
                    }
                    else if (string.IsNullOrWhiteSpace(clearText))
                    {
                        throw new ArgumentException(paramName: "clearText", message: "clearText cannot be empty.");
                    }

                    var cryptKeyBytes = ConvertToUTF8Bytes(ByteConverter, CryptKeyValue);
                    var hmacSaltBytes = ConvertToUTF8Bytes(ByteConverter, HmacSaltValue);
                    var clearBytes = ConvertToUTF8Bytes(ByteConverter, clearText);
                    var cryptBytes = Crypt(
                        keyBitSize: KeyBitSize,
                        blockBitSize: BlockBitSize,
                        secretMessage: clearBytes,
                        cryptKey: cryptKeyBytes,
                        authKey: hmacSaltBytes
                        );

                    var result = ConvertToBase64String(Base64Converter, cryptBytes);
                    return result;
                }

                public string Decrypt(string cipherText)
                {
                    if (cipherText == null)
                    {
                        throw new ArgumentNullException("cipherText");
                    }

                    var hmacSaltBytes = ConvertToUTF8Bytes(ByteConverter, HmacSaltValue);
                    var cryptKeyBytes = ConvertToUTF8Bytes(ByteConverter, CryptKeyValue);
                    var cipherTextBytes = ConvertFromBase64String(Base64Converter, cipherText);
                    var clearBytes = Decrypt(
                        keyBitSize: KeyBitSize,
                        blockBitSize: BlockBitSize,
                        encryptedMessage: cipherTextBytes,
                        cryptKey: cryptKeyBytes,
                        authKey: hmacSaltBytes
                        );

                    var result = ByteConverter.ConvertToString(clearBytes);
                    return result;
                }

                private string ConvertToBase64String(IBase64Converter base64Converter, IReadOnlyCollection<byte> input)
                {
                    var result = base64Converter.ToBase64String(input);
                    return result;
                }

                private static byte[] ConvertFromBase64String(IBase64Converter base64Converter, string input)
                {
                    var result = base64Converter.FromBase64String(input).EnsureArray();
                    return result;
                }

                private static byte[] ConvertToUTF8Bytes(IByteConverter byteConverter, string input)
                {
                    var result = byteConverter.ConvertToBytes(input).EnsureArray();
                    return result;
                }

                public static byte[] Crypt(int keyBitSize, int blockBitSize, byte[] secretMessage, byte[] cryptKey, byte[] authKey, byte[] nonSecretPayload = null)
                {
                    nonSecretPayload = nonSecretPayload ?? new byte[] { };

                    byte[] cipherText;
                    byte[] iv;

                    using (var aes = new AesManaged
                    {
                        KeySize = keyBitSize,
                        BlockSize = blockBitSize,
                        Mode = CipherMode.CBC,
                        Padding = PaddingMode.PKCS7
                    })
                    {
                        aes.GenerateIV();
                        iv = aes.IV;

                        using (var encrypter = aes.CreateEncryptor(cryptKey, iv))
                        using (var cipherStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write))
                            using (var binaryWriter = new BinaryWriter(cryptoStream))
                            {
                                binaryWriter.Write(secretMessage);
                            }

                            cipherText = cipherStream.ToArray();
                        }
                    }

                    using (var hmac = new HMACSHA256(authKey))
                    using (var encryptedStream = new MemoryStream())
                    {
                        using (var binaryWriter = new BinaryWriter(encryptedStream))
                        {
                            binaryWriter.Write(nonSecretPayload);
                            binaryWriter.Write(iv);
                            binaryWriter.Write(cipherText);
                            binaryWriter.Flush();

                            var tag = hmac.ComputeHash(encryptedStream.ToArray());
                            binaryWriter.Write(tag);
                        }
                        return encryptedStream.ToArray();
                    }
                }

                private static byte[] Decrypt(int keyBitSize, int blockBitSize, byte[] encryptedMessage, byte[] cryptKey, byte[] authKey, int nonSecretPayloadLength = 0)
                {
                    using (var hmac = new HMACSHA256(authKey))
                    {
                        var sentTag = new byte[hmac.HashSize / 8];
                        var calcTag = hmac.ComputeHash(encryptedMessage, 0, encryptedMessage.Length - sentTag.Length);
                        var ivLength = (blockBitSize / 8);

                        if (encryptedMessage.Length < sentTag.Length + nonSecretPayloadLength + ivLength)
                        {
                            return null;
                        }

                        Array.Copy(encryptedMessage, encryptedMessage.Length - sentTag.Length, sentTag, 0, sentTag.Length);

                        var compare = 0;
                        for (var i = 0; i < sentTag.Length; i++)
                        {
                            compare |= sentTag[i] ^ calcTag[i];
                        }

                        if (compare != 0)
                        {
                            return null;
                        }

                        using (var aes = new AesManaged
                        {
                            KeySize = keyBitSize,
                            BlockSize = blockBitSize,
                            Mode = CipherMode.CBC,
                            Padding = PaddingMode.PKCS7
                        })
                        {
                            var iv = new byte[ivLength];
                            Array.Copy(encryptedMessage, nonSecretPayloadLength, iv, 0, iv.Length);

                            using (var decrypter = aes.CreateDecryptor(cryptKey, iv))
                            using (var plainTextStream = new MemoryStream())
                            {
                                using (var decrypterStream = new CryptoStream(plainTextStream, decrypter, CryptoStreamMode.Write))
                                using (var binaryWriter = new BinaryWriter(decrypterStream))
                                {
                                    binaryWriter.Write(
                                        encryptedMessage,
                                        nonSecretPayloadLength + iv.Length,
                                        encryptedMessage.Length - nonSecretPayloadLength - iv.Length - sentTag.Length
                                    );
                                }
                                return plainTextStream.ToArray();
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        ///     ECHO
        /// </summary>
        public static class EchoPump
        {
            public static ICryptDecryptProvider NewInstance()
            {
                return new EchoCryptDecryptProvider();
            }

            private class EchoCryptDecryptProvider : ICryptProvider, ICryptDecryptProvider
            {
                public string Crypt(string clearText)
                {
                    if (clearText == null)
                    {
                        throw new ArgumentNullException("clearText");
                    }

                    return clearText;
                }

                public string Decrypt(string cipherText)
                {
                    if (cipherText == null)
                    {
                        throw new ArgumentNullException("cipherText");
                    }

                    return cipherText;
                }
            }
        }

        /// <summary>
        ///     MD5
        /// </summary>
        public static class MD5Pump
        {
            public static ICryptHashProvider NewInstance(IByteConverter byteConverter)
            {
                return NewInstance(
                    byteConverter: byteConverter,
                    hasher: MD5.Create()
                    );
            }

            public static ICryptHashProvider NewInstance(IByteConverter byteConverter, MD5 hasher)
            {
                return new MD5CryptHashProvider(
                    byteConverter: byteConverter,
                    hasher: hasher
                    );
            }

            private class MD5CryptHashProvider : ICryptHashProvider
            {
                private readonly IByteConverter ByteConverter;
                private readonly MD5 Hasher;

                public MD5CryptHashProvider(
                    IByteConverter byteConverter,
                    MD5 hasher
                    )
                {
                    ByteConverter = byteConverter;
                    Hasher = hasher;
                }

                public string Hash(string clearText)
                {
                    if (clearText == null)
                    {
                        throw new ArgumentNullException("clearText");
                    }

                    var result = HashCore(ByteConverter, Hasher, clearText);
                    return result;
                }

                private static string HashCore(IByteConverter byteConverter, System.Security.Cryptography.MD5 hasher, string value)
                {
                    // setup encoding, hash, and read byte array
                    var clearBytes = byteConverter.ConvertToBytes(value).EnsureArray();

                    // perform hashing operation
                    var hashBytes = hasher.ComputeHash(clearBytes);

                    // convert back to string
                    var result = hashBytes.ToHex();
                    return result;
                }
            }
        }

        /// <summary>
        ///     SHA 256
        /// </summary>
        public static class SHA256Pump
        {
            public static ICryptHashProvider NewInstance(IByteConverter byteConverter)
            {
                return NewInstance(
                    byteConverter: byteConverter,
                    hasher: SHA256.Create()
                    );
            }

            public static ICryptHashProvider NewInstance(IByteConverter byteConverter, SHA256 hasher)
            {
                return new SHA256CryptHashProvider(
                    byteConverter: byteConverter,
                    hasher: hasher
                    );
            }

            private class SHA256CryptHashProvider : ICryptHashProvider
            {
                private readonly IByteConverter ByteConverter;
                private readonly SHA256 Hasher;

                public SHA256CryptHashProvider(
                    IByteConverter byteConverter,
                    SHA256 hasher
                    )
                {
                    ByteConverter = byteConverter;
                    Hasher = hasher;
                }

                public string Hash(string clearText)
                {
                    if (clearText == null)
                    {
                        throw new ArgumentNullException("clearText");
                    }

                    var result = HashCore(ByteConverter, Hasher, clearText);
                    return result;
                }

                private static string HashCore(IByteConverter byteConverter, System.Security.Cryptography.SHA256 hasher, string value)
                {
                    // setup encoding, hash, and read byte array
                    var clearBytes = byteConverter.ConvertToBytes(value).EnsureArray();

                    // perform hashing operation
                    var hashBytes = hasher.ComputeHash(clearBytes);

                    // convert back to string
                    var result = hashBytes.ToHex();
                    return result;
                }
            }
        }

        /// <summary>
        ///     SHA 512
        /// </summary>
        public static class SHA512Pump
        {
            public static ICryptHashProvider NewInstance(IByteConverter byteConverter)
            {
                return NewInstance(
                    byteConverter: byteConverter,
                    hasher: SHA512.Create()
                    );
            }

            public static ICryptHashProvider NewInstance(IByteConverter byteConverter, SHA512 hasher)
            {
                return new SHA512CryptHashProvider(
                    byteConverter: byteConverter,
                    hasher: hasher
                    );
            }

            private class SHA512CryptHashProvider : ICryptHashProvider
            {
                private readonly IByteConverter ByteConverter;
                private readonly SHA512 Hasher;

                public SHA512CryptHashProvider(
                    IByteConverter byteConverter,
                    SHA512 hasher
                    )
                {
                    ByteConverter = byteConverter;
                    Hasher = hasher;
                }

                public string Hash(string clearText)
                {
                    if (clearText == null)
                    {
                        throw new ArgumentNullException("clearText");
                    }

                    var result = HashCore(ByteConverter, Hasher, clearText);
                    return result;
                }

                private static string HashCore(IByteConverter byteConverter, SHA512 hasher, string value)
                {
                    // setup encoding, hash, and read byte array
                    var clearBytes = byteConverter.ConvertToBytes(value).EnsureArray();

                    // perform hashing operation
                    var hashBytes = hasher.ComputeHash(clearBytes);

                    // convert back to string
                    var result = hashBytes.ToHex();
                    return result;
                }
            }
        }

        /// <summary>
        ///     SYSTEM RNG
        /// </summary>
        public static class SystemRngPump
        {
            public static IPsuedoRandomNumberGenerator NewInstance()
            {
                return new SystemRngProvider();
            }

            private class SystemRngProvider : IPsuedoRandomNumberGenerator
            {
                private readonly Random _Random;
                private readonly object _Lock;

                public SystemRngProvider()
                {
                    _Lock = new object();

                    lock (_Lock)
                        _Random = new Random();
                }

                public int Next()
                {
                    int result;

                    lock (_Lock)
                        result = _Random.Next();

                    return result;
                }

                public int Next(int maxValue)
                {
                    int result;

                    lock (_Lock)
                        result = _Random.Next(maxValue);
                    return result;
                }

                public int Next(int minValue, int maxValue)
                {
                    int result;

                    lock (_Lock)
                        result = _Random.Next(minValue, maxValue);

                    return result;
                }

                public double NextDouble()
                {
                    double result;

                    lock (_Lock)
                        result = _Random.NextDouble();

                    return result;
                }

                public double NextDouble(double maxValue)
                {
                    if (maxValue < 0.00)
                        throw new ArgumentOutOfRangeException("maxValue must be greater than or equal to zero.");

                    double result;

                    lock (_Lock)
                        result = _Random.NextDouble() * maxValue;

                    return result;
                }

                public double NextDouble(double minValue, double maxValue)
                {
                    if (maxValue < minValue)
                        throw new ArgumentOutOfRangeException("maxValue must be greater than or equal to minValue");

                    double result;

                    lock (_Lock)
                        result = (_Random.NextDouble() * (maxValue - minValue)) + minValue;

                    return result;
                }

                public void Dispose()
                {
                    //
                    // do nothing, rely on automagic garbage collection
                    //
                }
            }
        }
    }
}
