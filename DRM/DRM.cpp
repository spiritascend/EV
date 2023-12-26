#include "FNF/containers.h"
#include "lib/aes.hpp"
#include "FNF/utils.h"



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
				DecipherKey((__int64)&Key, 0, 0x10 - fourthbyteofEnv);


				if (0x10 != (uint64_t)fourthbyteofEnv)
					memmove(Key.Data, TrailBytes, (0x10 - fourthbyteofEnv));

				Envelope.erase(Envelope.begin() + (fourthbyteofEnv + EnvelopeSizeAfter5ByteRemoval - 0x10), Envelope.begin() + ((fourthbyteofEnv + EnvelopeSizeAfter5ByteRemoval - 0x10) + (0x10 - fourthbyteofEnv)));



				if (!(((int)Envelope.size() - (int)fifthbyteofEnv) % 16)) {
					struct AES_ctx ctx;

					uint8_t IV[16] = { 0 };
					uint8_t* encryptedintarray = reinterpret_cast<uint8_t*>(Envelope.data() + fifthbyteofEnv);


					AES_init_ctx_iv(&ctx, (const uint8_t*)Key.Data, IV);
					AES_CBC_decrypt_buffer(&ctx, encryptedintarray, Envelope.size() - fifthbyteofEnv);


					return ExtractObjectFromBuff(std::string((const char*)encryptedintarray));
				}

			}
		}
	}
}

int main()
{
	std::string EvString = "ENVELOPE_STRING";
	std::string Bearer = "BEARER_GOES_HERE"; // This includes the "bearer eg1~..."

	std::string DecryptedString = DecryptEnvelope(EvString, Bearer);

	std::cout << DecryptedString << std::endl;
}
