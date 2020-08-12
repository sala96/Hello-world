using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;

namespace JQAdmin.Common
{

	public class EncryptedString
	{
		private readonly string _value;

		public EncryptedString(string value)
		{
			_value = value;
		}

		public static implicit operator string(EncryptedString s)
		{
			return s._value;
		}

		public static implicit operator EncryptedString(string value)
		{
			if (value == null)
				return null;

			return new EncryptedString(value);
		}
	}

	public interface IEncryptedStringSerializer : IBsonSerializer<EncryptedString> { }

	public class EncryptedStringSerializer : SerializerBase<EncryptedString>, IEncryptedStringSerializer
	{
		//private readonly IDeterministicEncrypter _encrypter;
		private readonly string _encryptionKey;

		public EncryptedStringSerializer()
		{
			//_encrypter = encrypter;
			//_encryptionKey = configuration.GetSection("MongoDb")["EncryptionKey"];
		}

		public override EncryptedString Deserialize(BsonDeserializationContext context, BsonDeserializationArgs args)
		{
			var encryptedString = context.Reader.ReadString();
			return EncryptDecrypt.Decrypt(encryptedString);
		}

		public override void Serialize(BsonSerializationContext context, BsonSerializationArgs args, EncryptedString value)
		{
			var encryptedString = EncryptDecrypt.Encrypt(value);
			context.Writer.WriteString(encryptedString);
		}
	}
	public static class EncryptDecrypt
    {
 
		private static readonly Encoding encoding = Encoding.UTF8;

		public static string Encrypt(string plainText)
		{
			string key = "8UHjPgXZzXCGkhxV2QCnooyJexUzvJrO";
			try
			{
				RijndaelManaged aes = new RijndaelManaged();
				aes.KeySize = 256;
				aes.BlockSize = 128;
				aes.Padding = PaddingMode.PKCS7;
				aes.Mode = CipherMode.CBC;

				aes.Key = encoding.GetBytes(key);
				aes.GenerateIV();

				ICryptoTransform AESEncrypt = aes.CreateEncryptor(aes.Key, aes.IV);
				byte[] buffer = encoding.GetBytes(plainText);

				string encryptedText = Convert.ToBase64String(AESEncrypt.TransformFinalBlock(buffer, 0, buffer.Length));

				String mac = "";

				mac = BitConverter.ToString(HmacSHA256(Convert.ToBase64String(aes.IV) + encryptedText, key)).Replace("-", "").ToLower();

				var keyValues = new Dictionary<string, object>
				{
					{ "iv", Convert.ToBase64String(aes.IV) },
					{ "value", encryptedText },
					{ "mac", mac },
				};
				return Convert.ToBase64String(encoding.GetBytes(JsonConvert.SerializeObject(keyValues)));
			}
			catch (Exception e)
			{
				throw new Exception("Error encrypting: " + e.Message);
			}
		}

		public static string Decrypt(string plainText)
		{
			string key = "8UHjPgXZzXCGkhxV2QCnooyJexUzvJrO";
			try
			{
				RijndaelManaged aes = new RijndaelManaged();
				aes.KeySize = 256;
				aes.BlockSize = 128;
				aes.Padding = PaddingMode.PKCS7;
				aes.Mode = CipherMode.CBC;
				aes.Key = encoding.GetBytes(key);

				// Base 64 decode
				byte[] base64Decoded = Convert.FromBase64String(plainText);
				string base64DecodedStr = encoding.GetString(base64Decoded);

				// JSON Decode base64Str
				var payload = JsonConvert.DeserializeObject<Dictionary<string, string>>(base64DecodedStr);

				aes.IV = Convert.FromBase64String(payload["iv"]);

				ICryptoTransform AESDecrypt = aes.CreateDecryptor(aes.Key, aes.IV);
				byte[] buffer = Convert.FromBase64String(payload["value"]);

				return encoding.GetString(AESDecrypt.TransformFinalBlock(buffer, 0, buffer.Length));
			}
			catch (Exception e)
			{
				throw new Exception("Error decrypting: " + e.Message);
			}
		}

		static byte[] HmacSHA256(String data, String key)
		{
			using (HMACSHA256 hmac = new HMACSHA256(encoding.GetBytes(key)))
			{
				return hmac.ComputeHash(encoding.GetBytes(data));
			}
		}
	}
}
