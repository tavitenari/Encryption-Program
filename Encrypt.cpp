#include "stdafx.h"
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS
/*
Encryption program makes use of OpenSSL library, which includes SHA-512, HMAC, PBKDF2, and AES-256-CBC functions
*/
#include <openssl\aes.h>
#include <openssl\hmac.h>
#include <openssl\sha.h>
#include <openssl\evp.h>
#include <iostream>
#include <iomanip>
#include <string>
using namespace std;

const unsigned char* Salt32();
void PBKDF2_HMAC_SHA_512_string(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult);
void print_data(const void* data, int len);

void main()
{
	/*Message to be encrypted*/
	const char* pass = "This is a secret";
	cout << "Original input: " << pass << endl << endl;

	const int PASS_SIZE = sizeof(pass) * 2;
	unsigned char enc_out[PASS_SIZE];
	unsigned char dcr_out[PASS_SIZE];
	
	/*Salt for keys*/
	const unsigned char* salt_masterKey = Salt32();
	const unsigned char* salt_encKey = Salt32();
	const unsigned char* salt_hmacKey = Salt32();
	
	const int outputBytes = 32;
	const int iterations = 100000;
	const int keysize = 2 * outputBytes + 1; // 2*outputBytes+1 is 2 hex bytes per binary byte, and one character at the end for the string-terminating \0

	/*Declaration of Keys*/
	char masterKey[keysize];
	char encKey[keysize];
	char hmacKey[keysize];
	
	PBKDF2_HMAC_SHA_512_string(pass, salt_masterKey, iterations, outputBytes, masterKey);
	unsigned char* digest;
	digest = HMAC(EVP_sha512(), masterKey, outputBytes, salt_encKey, outputBytes, NULL, NULL);
	for (int i = 0; i < 32; i++)
		sprintf(&encKey[i * 2], "%02x", (unsigned int)digest[i]);
	digest = HMAC(EVP_sha512(), masterKey, outputBytes, salt_hmacKey, outputBytes, NULL, NULL);
	for (int i = 0; i < 32; i++)
		sprintf(&hmacKey[i * 2], "%02x", (unsigned int)digest[i]);

	cout << "Master Key: " << masterKey << endl;
	cout << setw(10) << "salt: " << salt_masterKey << endl;
	cout << "Encrypted Key: " << encKey << endl;
	cout << setw(10) << "salt: " << salt_encKey << endl;
	cout << "HMAC Key: " << hmacKey << endl;
	cout << setw(10) << "salt: " << salt_hmacKey << endl;

	/*Declaration of IV*/
	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, 0x00, AES_BLOCK_SIZE);

	cout << "IV: " << AES_BLOCK_SIZE << endl << endl;
	
	/*ENCRYPTION*/
	
		AES_KEY enc_key, dec_key;
		AES_set_encrypt_key((const unsigned char*)encKey, 256, &enc_key);
		
		/*AES-256-CBC*/
		AES_cbc_encrypt((const unsigned char*)pass, enc_out, PASS_SIZE, &enc_key, iv, AES_ENCRYPT);

		/*HMAC of Encrypted Message and HMAC Key*/
		char checkKey[keysize];
		digest = HMAC(EVP_sha512(), hmacKey, outputBytes, enc_out, outputBytes, NULL, NULL);
		for (int i = 0; i < 32; i++)
			sprintf(&checkKey[i * 2], "%02x", (unsigned int)digest[i]);

		cout << "Encrypted message: ";
		print_data(enc_out, PASS_SIZE);
		cout << endl;

	/*DECRYPTION*/
	
		memset(iv, 0x00, AES_BLOCK_SIZE);
		AES_set_decrypt_key((const unsigned char*)encKey, 256, &dec_key);

		
		char checkKey2[keysize];
		digest = HMAC(EVP_sha512(), hmacKey, outputBytes, enc_out, outputBytes, NULL, NULL);
		for (int i = 0; i < 32; i++)
			sprintf(&checkKey2[i * 2], "%02x", (unsigned int)digest[i]);
		
		/*Check HMAC of encrypted data*/
		if ((string)checkKey == (string)checkKey2)
		{
			AES_cbc_encrypt(enc_out, dcr_out, PASS_SIZE, &dec_key, iv, AES_DECRYPT);
		}
		else
		{
			abort();
		}

		cout << "Decrypted message: ";
		for (int i = 0; i < PASS_SIZE; i++)
		{
			cout << dcr_out[i];
		}
		cout << endl << endl;

	system("pause");
}


/*FUNCTION IMPLEMENTATION*/

const unsigned char* Salt32() //Source: http://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
{
	string str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	string newstr;
	int pos;
	while (newstr.size() != 32)
	{
		pos = ((rand() % (str.size() - 1)));
		newstr += str.substr(pos, 1);
	}
	const unsigned char* salt = (unsigned char*)newstr.c_str();
	return salt;
}

void PBKDF2_HMAC_SHA_512_string(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult) //Source: https://github.com/Anti-weakpasswords/PBKDF2-Gplusplus-Cryptopp-library/blob/master/pbkdf2_crypto%2B%2B.cpp
{
	unsigned int i;
	unsigned char digest[32];
	PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, 32, iterations, EVP_sha512(), outputBytes, digest);
	for (i = 0; i < sizeof(digest); i++)
		sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
}

void print_data(const void* data, int len)
{
	const unsigned char * p = (const unsigned char*)data;
	for (int i = 0; i < len; ++i)
		printf("%02X ", *p++);
	printf("\n");
}