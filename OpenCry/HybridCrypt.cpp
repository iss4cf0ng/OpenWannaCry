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
	if (!m_pEncRSA)
	{
		m_pEncRSA = new EZRSA();
		if (!m_pEncRSA)
		{
			DEBUG("Initialize m_pEncRSA failed.\n");
			return FALSE;
		}
	}

	return m_pEncRSA->fnbImport(BCRYPT_RSAPUBLIC_BLOB, pbPublicBlob, cbPublicBlob);
}

BOOL HybridCrypt::fnImportPublicKey(LPCTSTR pPublicBlobFile)
{
	if (!m_pEncRSA)
	{
		m_pEncRSA = new EZRSA();
		if (!m_pEncRSA)
		{
			DEBUG("Initialize m_pEncRSA failed.\n");
			return FALSE;
		}
	}

	return m_pEncRSA->fnbImport(BCRYPT_RSAPUBLIC_BLOB, pPublicBlobFile);
}

BOOL HybridCrypt::fnImportPrivateKey(PUCHAR pbPrivateBlob, ULONG cbPrivateBlob)
{
	if (!m_pDecRSA)
	{
		m_pDecRSA = new EZRSA();
		if (!m_pDecRSA)
		{
			DEBUG("Initialize m_pDecRSA failed.\n");
			return FALSE;
		}
	}

	return m_pDecRSA->fnbImport(BCRYPT_RSAPRIVATE_BLOB, pbPrivateBlob, cbPrivateBlob);
}

BOOL HybridCrypt::fnImportPrivateKey(LPCTSTR pPrivateBlobFile)
{
	if (!m_pDecRSA)
	{
		m_pDecRSA = new EZRSA();
		if (!m_pDecRSA)
		{
			DEBUG("Initialize m_pDecRSA failed.\n");
			return FALSE;
		}
	}

	return m_pDecRSA->fnbImport(BCRYPT_RSAPRIVATE_BLOB, pPrivateBlobFile);
}

BOOL HybridCrypt::fnEncrypt(LPCTSTR pFileName)
{
	UCHAR abMagic[8];
	ULONG cbCipherKey;
	UCHAR abCipherKey[0x200];
	UCHAR uEncryptOP = EZH_ENCRYPT;
	UCHAR nCryptType = 0;
	LARGE_INTEGER ddwFileSize;
	
	PEZAES pAES = NULL;
	UCHAR abKey[16];
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hWrite = INVALID_HANDLE_VALUE;

	ULONG cbRead = NULL;
	ULONG cbWrite = NULL;

	FILETIME tsCreationTime;
	FILETIME tsLastModifiedTime;
	FILETIME tsLastAccessedTime;

	PUCHAR pbInBlock = m_InBuffer;
	ULONG cbInBlock = 0;
	PUCHAR pbOutBlock = m_OutBuffer;
	ULONG cbOutBlock = 0;

	TCHAR pTempFile[MAX_PATH];
	TCHAR pTarget[MAX_PATH];

	if (m_pEncRSA)
	{
		DEBUG("m_pEncRSA is NULL, please call ImportPublicKey()\n");
		return FALSE;
	}

	DEBUG("Encrypt %s\n", pFileName);
	_tcscpy_s(pTarget, MAX_PATH, pFileName);

	LPTSTR pSuffix = (LPTSTR)_tcsrchr(pTarget, _T('.'));
	if (!pSuffix)
	{
		_tcscat_s(pTarget, MAX_PATH, EZH_SUFFIX_CIPHER);
	}
	else
	{
		if (!_tcsicmp(pSuffix, EZH_SUFFIX_CIPHER) || !_tcsicmp(pSuffix, EZH_SUFFIX_TEMP))
		{
			return TRUE;
		}
		else
		{
			_tcscat_s(pSuffix, MAX_PATH - _tcslen(pFileName), EZH_SUFFIX_CIPHER);
		}
	}

	if (!(hFile = CreateFile(pFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)))
	{
		DEBUG("Open %s fpr read.\n", pFileName);
		return FALSE;
	}

	DEBUG("Open %s fpr read.\n", pFileName);
	ddwFileSize.QuadPart = 0;
	GetFileTime(hFile, &tsCreationTime, &tsLastAccessedTime, &tsLastModifiedTime);

	BOOL bResult = ReadFile(hFile, abMagic, sizeof(abMagic), &cbRead, 0);

}

BOOL HybridCrypt::fnDecrypt(LPCTSTR pFileName)
{

}
