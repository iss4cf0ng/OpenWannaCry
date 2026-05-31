#pragma once

#include <Windows.h>
#include <bcrypt.h>
#include <vector>
#include <string>

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
public:
	HybridCrypt() = default;
	~HybridCrypt() = default;

	
};

