

//===== File Encryption Engine ========//

/* This library contains all the methods for encryption and decryption of any files
 * Author - Brian Philemon
 * Version 2.0
 * Date: 05 Jan 2019
 * Publisher: Brian Philemon
 * 
 * 
 * */
using System;
using System.IO;
using System.Threading;
using System.Diagnostics;
using System.Security.Cryptography;

//---- crypto namspace -----//
namespace Crypto
{

   public class CryptoEngine
    {
      public  static void Main(string[] args)
        {
            // --- path to the source file/raw files
            string raw_file_path = null; /*"D:\\vid\\Nrture.MKV"*/;

            //--- path to the output file (.skt) 
            string encrypted_file_path = null;/*"D:\\vid\\encrypted.skt";*/

            //--- encryption key
            string encrypt_key = "!@3ewutrju.34FDSw_)^";
            Console.WriteLine("Enter file source path\n");
            raw_file_path = Console.ReadLine();
            Console.WriteLine("Enter location to save file:\n");
            encrypted_file_path = Console.ReadLine() + ".skt";
            
            //--- path to the source file {for decryption} (.skt) 
            string decrypted_file_path = "D:\\vid\\decrypted.MKV";
            decrypted_file_path = encrypted_file_path + ".MKV";
            try
            {
                EncryptFile(encrypt_key, raw_file_path, encrypted_file_path);
                DecryptFile(encrypt_key, encrypted_file_path, decrypted_file_path);
                Console.WriteLine("Encryption and decryption done successfully\n\n");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Could not encrypt the file!\n\n\n{e}\n\n");
            }

            Console.ReadKey();
        }

        //Encrypt input video ++ Save Encrypted
        public static void EncryptFile(string encrypt_key,
            string in_file, string out_file)
        {
            CryptFile(encrypt_key, in_file, out_file, true);
        }

        //Decrypt input ++ Stream Decrypted
        public static void DecryptFile(string encrypt_key,
            string in_file, string out_file)
        {
            CryptFile(encrypt_key, in_file, out_file, false);
        }

        public static void CryptFile(string encrypt_key,
         string in_file, string out_file, bool encrypt)
        {
            // Create input and output file streams.
            using (FileStream in_stream =
                new FileStream(in_file, FileMode.Open, FileAccess.Read))
            {
                using (FileStream out_stream =
                    new FileStream(out_file, FileMode.Create,
                        FileAccess.Write))
                {
                    // Encrypt/decrypt the input stream into
                    // the output stream.
                    CryptStream(encrypt_key, in_stream, out_stream, encrypt);
                }
            }
        }

        // Encrypt the data in the input stream into the output stream.
        public static void CryptStream(string encrypt_key,
            Stream in_stream, Stream out_stream, bool encrypt)
        {
            // Make an AES service provider.
            AesCryptoServiceProvider aes_provider =
                new AesCryptoServiceProvider();

            // Find a valid key size for this provider.
            int key_size_bits = 0;
            for (int i = 1024; i > 1; i--)
            {
                if (aes_provider.ValidKeySize(i))
                {
                    key_size_bits = i;
                    break;
                }
            }
            Debug.Assert(key_size_bits > 0);
            Console.WriteLine("Key size: " + key_size_bits);

            // Get the block size for this provider.
            int block_size_bits = aes_provider.BlockSize;

            // Generate the key and initialization vector.
            byte[] key = null;
            byte[] iv = null;
            byte[] salt = { 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6,
        0xF1, 0xF0, 0xEE, 0x21, 0x22, 0x45 };
            MakeKeyAndIV(encrypt_key, salt, key_size_bits, block_size_bits,
                out key, out iv);

            // Make the encryptor or decryptor.
            ICryptoTransform crypto_transform;
            if (encrypt)
            {
                crypto_transform = aes_provider.CreateEncryptor(key, iv);
            }
            else
            {
                crypto_transform = aes_provider.CreateDecryptor(key, iv);
            }

            // Attach a crypto stream to the output stream.
            // Closing crypto_stream sometimes throws an
            // exception if the decryption didn't work
            // (e.g. if we use the wrong encrypt_key).
            try
            {
                using (CryptoStream crypto_stream =
                    new CryptoStream(out_stream, crypto_transform,
                        CryptoStreamMode.Write))
                {
                    // Encrypt or decrypt the file.
                    const int block_size = 1024;
                    byte[] buffer = new byte[block_size];
                    int bytes_read;
                    while (true)
                    {
                        // Read some bytes.
                        bytes_read = in_stream.Read(buffer, 0, block_size);
                        if (bytes_read == 0) break;

                        // Write the bytes into the CryptoStream.
                        crypto_stream.Write(buffer, 0, bytes_read);
                    }
                } // using crypto_stream 
            }
            catch
            {
            }

            crypto_transform.Dispose();
        }

        // Use the encrypt_key to generate key bytes.
        private static void MakeKeyAndIV(string encrypt_key, byte[] salt,
            int key_size_bits, int block_size_bits,
            out byte[] key, out byte[] iv)
        {
            Rfc2898DeriveBytes derive_bytes =
                new Rfc2898DeriveBytes(encrypt_key, salt, 1000);

            key = derive_bytes.GetBytes(key_size_bits / 8);
            iv = derive_bytes.GetBytes(block_size_bits / 8);
        }
    }
}
