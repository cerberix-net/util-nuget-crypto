using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Cerberix.Crypto.Core;
using Cerberix.Extension.Core;
using Cerberix.Serialization.Core;

namespace Cerberix.Crypto.DotNet.Logic
{
    /// <summary>
    ///		Implements AES256+HMAC crypt/decrypt provider (ICryptProvider, ICryptDecryptProvider)
    /// </summary>
    internal class AES256PlusHMACCryptDecryptProvider : ICryptProvider, ICryptDecryptProvider
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
