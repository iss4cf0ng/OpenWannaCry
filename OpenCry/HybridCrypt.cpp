// HybridCrypt.cpp

#include "HybridCrypt.h"
#include "Common.h"

static BOOL fnbGenRandom(PUCHAR pbBuffer, ULONG cbBuffer)
{
	NTSTATUS status = BCryptGenRandom(NULL, pbBuffer, cbBuffer, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!NT_SUCCESS(status))
	{
		DEBUG("BCryptGenRandom returns 0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}

HybridCrypt::HybridCrypt()
{
	m_pEncRSA = NULL;
	m_pDecRSA = NULL;
	m_InBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, EZH_IOBUFFERSIZE);
	m_OutBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, EZH_IOBUFFERSIZE);

	return;
}

HybridCrypt::~HybridCrypt()
{
	if (m_pEncRSA)
	{
		delete m_pEncRSA;
		m_pEncRSA = NULL;
	}

	if (m_pDecRSA)
	{
		delete m_pDecRSA;
		m_pDecRSA = NULL;
	}

	if (m_InBuffer)
	{
		HeapFree(GetProcessHeap(), 0, m_InBuffer);
		m_InBuffer = NULL;
	}

	if (m_OutBuffer)
	{
		HeapFree(GetProcessHeap(), 0, m_OutBuffer);
		m_OutBuffer = NULL;
	}

	return;
}

BOOL HybridCrypt::fnGenKey()
{
	if (!m_pEncRSA)
	{
		m_pEncRSA = new EZRSA();
		if (!m_pEncRSA)
			return FALSE;
	}

	return m_pEncRSA->fnbGenKey();
}

BOOL HybridCrypt::fnImportPublicKey(PUCHAR pbPublicBlob, ULONG cbPublicBlob)
{

}

BOOL HybridCrypt::fnImportPublicKey(LPCTSTR pPublicBlobFile)
{

}

BOOL HybridCrypt::fnImportPrivateKey(PUCHAR pbPrivateBlob, ULONG cbPrivateBlob)
{

}

BOOL HybridCrypt::fnImportPrivateKey(LPCTSTR pPrivateBlobFile)
{

}

BOOL HybridCrypt::fnEncrypt(LPCTSTR pFileName)
{

}

BOOL HybridCrypt::fnDecrypt(LPCTSTR pFileName)
{

}
