#pragma once



#include <emmintrin.h>
#include <wmmintrin.h>
#include <cstdint>


#define AES256_ROUND_COUNT 14

#define AES_INIT_DEC_X86(ctx, x, y, rcon)         \
{                                                 \
    __m128i z, t;                                 \
    ctx = _mm_aesimc_si128(y);                    \
    z = _mm_aeskeygenassist_si128(y, rcon);       \
    z = _mm_shuffle_epi32(z, rcon ? 0xff : 0xaa); \
    t = _mm_slli_si128(x, 4);                     \
    x = _mm_xor_si128(x, t);                      \
    t = _mm_slli_si128(t, 4);                     \
    x = _mm_xor_si128(x, t);                      \
    t = _mm_slli_si128(t, 4);                     \
    x = _mm_xor_si128(x, t);                      \
    x = _mm_xor_si128(x, z);                      \
}




static volatile void AesDecryptX86(const void* Key, void* Contents, uint64_t NumBytes)
{
	const __m128i* Key128 = reinterpret_cast<const __m128i*>(Key);
	__m128i x = _mm_loadu_si128(Key128 + 0);
	__m128i y = _mm_loadu_si128(Key128 + 1);

	__m128i DKey[AES256_ROUND_COUNT + 1];
	DKey[14] = x;
	AES_INIT_DEC_X86(DKey[13], x, y, 0x01);
	AES_INIT_DEC_X86(DKey[12], y, x, 0x00);
	AES_INIT_DEC_X86(DKey[11], x, y, 0x02);
	AES_INIT_DEC_X86(DKey[10], y, x, 0x00);
	AES_INIT_DEC_X86(DKey[9], x, y, 0x04);
	AES_INIT_DEC_X86(DKey[8], y, x, 0x00);
	AES_INIT_DEC_X86(DKey[7], x, y, 0x08);
	AES_INIT_DEC_X86(DKey[6], y, x, 0x00);
	AES_INIT_DEC_X86(DKey[5], x, y, 0x10);
	AES_INIT_DEC_X86(DKey[4], y, x, 0x00);
	AES_INIT_DEC_X86(DKey[3], x, y, 0x20);
	AES_INIT_DEC_X86(DKey[2], y, x, 0x00);
	AES_INIT_DEC_X86(DKey[1], x, y, 0x40);
	DKey[0] = x;

	__m128i* Data = reinterpret_cast<__m128i*>(Contents);
	while (NumBytes >= 32)
	{
		__m128i Block0 = _mm_loadu_si128(Data + 0);
		__m128i Block1 = _mm_loadu_si128(Data + 1);

		Block0 = _mm_xor_si128(Block0, DKey[0]);
		Block1 = _mm_xor_si128(Block1, DKey[0]);
		Block0 = _mm_aesdec_si128(Block0, DKey[1]);
		Block1 = _mm_aesdec_si128(Block1, DKey[1]);
		Block0 = _mm_aesdec_si128(Block0, DKey[2]);
		Block1 = _mm_aesdec_si128(Block1, DKey[2]);
		Block0 = _mm_aesdec_si128(Block0, DKey[3]);
		Block1 = _mm_aesdec_si128(Block1, DKey[3]);
		Block0 = _mm_aesdec_si128(Block0, DKey[4]);
		Block1 = _mm_aesdec_si128(Block1, DKey[4]);
		Block0 = _mm_aesdec_si128(Block0, DKey[5]);
		Block1 = _mm_aesdec_si128(Block1, DKey[5]);
		Block0 = _mm_aesdec_si128(Block0, DKey[6]);
		Block1 = _mm_aesdec_si128(Block1, DKey[6]);
		Block0 = _mm_aesdec_si128(Block0, DKey[7]);
		Block1 = _mm_aesdec_si128(Block1, DKey[7]);
		Block0 = _mm_aesdec_si128(Block0, DKey[8]);
		Block1 = _mm_aesdec_si128(Block1, DKey[8]);
		Block0 = _mm_aesdec_si128(Block0, DKey[9]);
		Block1 = _mm_aesdec_si128(Block1, DKey[9]);
		Block0 = _mm_aesdec_si128(Block0, DKey[10]);
		Block1 = _mm_aesdec_si128(Block1, DKey[10]);
		Block0 = _mm_aesdec_si128(Block0, DKey[11]);
		Block1 = _mm_aesdec_si128(Block1, DKey[11]);
		Block0 = _mm_aesdec_si128(Block0, DKey[12]);
		Block1 = _mm_aesdec_si128(Block1, DKey[12]);
		Block0 = _mm_aesdec_si128(Block0, DKey[13]);
		Block1 = _mm_aesdec_si128(Block1, DKey[13]);
		Block0 = _mm_aesdeclast_si128(Block0, DKey[14]);
		Block1 = _mm_aesdeclast_si128(Block1, DKey[14]);

		_mm_storeu_si128(Data + 0, Block0);
		_mm_storeu_si128(Data + 1, Block1);
		Data += 2;
		NumBytes -= 32;
	}

	if (NumBytes != 0)
	{
		__m128i Block = _mm_loadu_si128(Data);

		Block = _mm_xor_si128(Block, DKey[0]);
		Block = _mm_aesdec_si128(Block, DKey[1]);
		Block = _mm_aesdec_si128(Block, DKey[2]);
		Block = _mm_aesdec_si128(Block, DKey[3]);
		Block = _mm_aesdec_si128(Block, DKey[4]);
		Block = _mm_aesdec_si128(Block, DKey[5]);
		Block = _mm_aesdec_si128(Block, DKey[6]);
		Block = _mm_aesdec_si128(Block, DKey[7]);
		Block = _mm_aesdec_si128(Block, DKey[8]);
		Block = _mm_aesdec_si128(Block, DKey[9]);
		Block = _mm_aesdec_si128(Block, DKey[10]);
		Block = _mm_aesdec_si128(Block, DKey[11]);
		Block = _mm_aesdec_si128(Block, DKey[12]);
		Block = _mm_aesdec_si128(Block, DKey[13]);
		Block = _mm_aesdeclast_si128(Block, DKey[14]);

		_mm_storeu_si128(Data, Block);
	}
}