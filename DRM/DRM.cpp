
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


std::string DecryptEnvelope(const std::string& EVString, const std::string& Bearer) {
	auto Envelope = decodeBase64(EVString);
	if (Envelope.empty()) {
		throw std::runtime_error("Failed to decode envelope");
	}

	if (Envelope[0] != 1) {
		throw std::runtime_error("Envelope header is invalid");
	}

	int fourthbyteofEnv = Envelope[3];
	int fifthbyteofEnv = Envelope[4];

	Envelope.erase(Envelope.begin(), Envelope.begin() + 5);

	if (static_cast<int>(Bearer.length()) >= fourthbyteofEnv) {
		auto subkey = std::vector<unsigned char>(Bearer.end() - fourthbyteofEnv, Bearer.end());

		if (subkey.size() == static_cast<size_t>(fourthbyteofEnv)) {
			auto finalkey = std::vector<unsigned char>(Envelope.end() - (0x10 - fourthbyteofEnv), Envelope.end());
			finalkey.insert(finalkey.end(), subkey.begin(), subkey.end());

			size_t startIndex = fourthbyteofEnv + Envelope.size() - 0x10;
			size_t endIndex = startIndex + (0x10 - fourthbyteofEnv);

			Envelope.erase(Envelope.begin() + startIndex, Envelope.begin() + endIndex);

			if ((Envelope.size() - fifthbyteofEnv) % AES_BLOCKLEN == 0) {
				std::vector<unsigned char> decryptedText(Envelope.size());
				std::vector<unsigned char> IV(AES_BLOCKLEN, 0);

				struct AES_ctx ctx;
				AES_init_ctx_iv(&ctx, finalkey.data(), IV.data());
				AES_CBC_decrypt_buffer(&ctx, Envelope.data() + fifthbyteofEnv, Envelope.size() - fifthbyteofEnv);

				return ParseJsonFromDecryptedBlob(std::string(Envelope.begin() + fifthbyteofEnv, Envelope.end()));
			}
		}
		else {
			throw std::runtime_error("Invalid bearer subkey length");
		}
	}

	return "";
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
			printf("%02x\n", BufferDecryptionKey.data()[0]);

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



//#define USE_BLURL_DECRYTION


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
	
	



	