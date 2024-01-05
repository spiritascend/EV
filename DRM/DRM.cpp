#include "FNF/containers.h"
#include "lib/aes.hpp"
#include "FNF/utility.h"
#include <openssl/md5.h>
#include "FNF/AES_Custom.h"





/*
This project was more for educational purposes only. This is not to be used maliciously or to pirate content. I made this purely because I was bored and had nothing else to do.
Thank you samuel (@samuels1v on twitter) for assisting me in decompiling the function (It made this a lot quicker).
*/



/*
	To make the key "useable" replace all the -'s in the k value to +'s and all the _'s into /'s and then base64 decode into hex and thats the encryption key string
*/


void* DecipherKey(__int64 a1, int a2, int a3) {

	auto v3 = *(uint64_t*)(a1 + 8);
	auto v5 = (int)a3;
	auto v6 = a2;
	*(uint64_t*)(a1 + 8) = v3 + a3;
	if (a3 > *(__int64*)(a1 + 0xC) - v3)
		*(uint64_t*)(a1 + 8) = (uint64_t)_aligned_realloc(&v3, 8, 1);


	auto result = memmove((void*)(*(__int64*)a1 + v6 + v5), (const void*)(*(__int64*)a1 + v6), (unsigned int)(v3 - v6));
	return result;
}


std::string DecryptEnvelope(std::string EvString, std::string Bearer) {
	std::vector<unsigned char> Envelope = decodeBase64(EvString);

	if (Envelope[0] == 1) {
		auto fourthbyteofEnv = Envelope[3];
		auto fifthbyteofEnv = Envelope[4];

		Envelope.erase(Envelope.begin(), Envelope.begin() + 5);

		auto EnvelopeSizeAfter5ByteRemoval = Envelope.size();

		if (Bearer.size() >= fourthbyteofEnv) {
			auto subkey = Bearer.substr(Bearer.length() - fourthbyteofEnv);

			if (subkey.size() == fourthbyteofEnv) {
				auto TrailBytes = (char*)Envelope.data() + (int)Envelope.size() - (0x10 - fourthbyteofEnv);

				auto Key = Conv_StringToCharArray(subkey);
				DecipherKey((__int64) & Key, 0, 0x10 - fourthbyteofEnv);


				if (0x10 != (uint64_t)fourthbyteofEnv)
					memmove(Key.Data, TrailBytes, (0x10 - fourthbyteofEnv));

				Envelope.erase(Envelope.begin() + (fourthbyteofEnv + EnvelopeSizeAfter5ByteRemoval - 0x10), Envelope.begin() + ((fourthbyteofEnv + EnvelopeSizeAfter5ByteRemoval - 0x10) + (0x10 - fourthbyteofEnv)));



				if (!(((int)Envelope.size() - (int)fifthbyteofEnv) % 16)) {
					struct AES_ctx ctx;

					uint8_t IV[16] = { 0 };
					uint8_t* encryptedintarray = reinterpret_cast<uint8_t*>(Envelope.data() + fifthbyteofEnv);


					AES_init_ctx_iv(&ctx, (const uint8_t*)Key.Data, IV);
					AES_CBC_decrypt_buffer(&ctx, encryptedintarray, Envelope.size() - fifthbyteofEnv);


					std::string result = ExtractObjectFromBuff(std::string((const char*)encryptedintarray));



					return result;
				}

			}
		}
	}
}

struct Envelope
{
	uint8_t Magic;
	uint8_t Reserved_0;
	uint8_t HashSize;
	uint8_t Reserved_1;
	uint8_t KeySize;

	uint8_t Buffer[256];
};

std::string DecryptEV_BLURL(std::string EV)
{
	std::ifstream file("keys.bin", std::ios::in | std::ios::binary);

	if (!file) {
		std::cerr << "File 'keys.bin' not found in the current directory." << std::endl;
		return "NONE";
	}


	std::vector<unsigned char> Data = decodeBase64(EV);
	Envelope* envelope = (Envelope*)Data.data();

	if (envelope->Magic != 0x1) printf("Invalid envelope! (Bad Magic)");
	if (envelope->KeySize <= 0) printf("Invalid envelope! (Bad Key)");
	if (envelope->HashSize <= 0) printf("Invalid envelope! (Bad Hash)");

	std::string Hash;
	uint8_t EncryptedKey[0x10];

	for (int i = 0; i < envelope->HashSize; i++)
		Hash += envelope->Buffer[i];

	for (int i = 0; i < envelope->KeySize; i++)
		EncryptedKey[i] = envelope->Buffer[envelope->HashSize + i];

	std::vector<char> Buffer(4);
	std::vector<uint8_t> BufferDecryptionKey(32);
	char FirstByteOfHash;

	while (true) {
		if (!file.read(Buffer.data(), 4))  break;
		if (!file.get(FirstByteOfHash)) break;

		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, Buffer.data(), 4);
		MD5_Update(&ctx, Hash.data(), envelope->HashSize);

		unsigned char hash[20];
		MD5_Final(hash, &ctx);

		if (hash[0] == (unsigned char)FirstByteOfHash)
		{
			file.seekg(0xF, std::ios::cur);
			if (!file.read((char*)BufferDecryptionKey.data(), 32)) break;
			
			AesDecryptX86(BufferDecryptionKey.data(), EncryptedKey, 16);

			file.close();

			return arrayToHexString(EncryptedKey,16);
		}

		file.seekg(0x2f, std::ios::cur);
		if (file.eof() || file.fail()) break;
	}
}



#define USE_BLURL_DECRYTION


int main()
{
#ifndef USE_BLURL_DECRYTION
	std::string EvString = "INSERT_ENV_HERE";
	std::string Bearer = "INSERT_BEARER_HERE"; // This includes the "bearer eg1~..."

	std::string DecryptedString = DecryptEnvelope(EvString, Bearer);

	printf("Decrypted Payload : %s\n", DecryptedString.c_str());
#endif



/*Make sure that the keys.bin file (Located in the dependencies folder) is in the same directory as the executable when dealing with blurl decryption*/
#ifdef USE_BLURL_DECRYTION
	std::string key = DecryptEV_BLURL("INSERT_EV_HERE");
	std::cout << key << std::endl;
#endif

	return 0;
}
	
	



	