// EZRSA.cpp

#include "EZRSA.h"
#include "Common.h"

EZRSA::EZRSA()
{
	m_hProv = INVALID_HANDLE_VALUE;
	m_hKey = INVALID_HANDLE_VALUE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&m_hProv, BCRYPT_RSA_ALGORITHM, nullptr, 0)))
	{
		DEBUG("BCryptOpenAlgorithmProvider returns 0x%x\n", status);
		return;
	}

	m_hKey = INVALID_HANDLE_VALUE;

	return;
}

EZRSA::~EZRSA()
{
	if (INVALID_HANDLE_VALUE != m_hProv)
	{
		BCryptCloseAlgorithmProvider(m_hProv, 0);
		m_hProv = INVALID_HANDLE_VALUE;
	}

	if (INVALID_HANDLE_VALUE != m_hKey)
	{
		BCryptDestroyKey(m_hKey);
		m_hKey = INVALID_HANDLE_VALUE;
	}

	return;
}

BOOL EZRSA::fnbGenKey()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status = BCryptGenerateKeyPair(m_hProv, &m_hKey, 2048, 0)))
	{
		DEBUG("BCryptGenerateKey returns 0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}

BOOL EZRSA::fnbImport(LPCWSTR pKeyType, PUCHAR pbBlob, ULONG cbBlob)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!NT_SUCCESS(status = BCryptImportKeyPair(m_hProv, NULL, pKeyType, &m_hKey, pbBlob, cbBlob, 0)))
	{
		DEBUG("BCryptImportKeyPair returns 0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}

BOOL EZRSA::fnbImport(LPCWSTR pKeyType, LPCTSTR pFileName)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	UCHAR abBlob[4096];
	ULONG cbBlob = 0;
	ULONG cbFile = 0;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (INVALID_HANDLE_VALUE == (hFile = CreateFile(pFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)))
	{
		DEBUG("Open %s failed\n", pFileName);
		return FALSE;
	}

	cbFile = GetFileSize(hFile, NULL);
	if (sizeof(abBlob) < cbFile)
	{
		DEBUG("Buffer size %d is not enough for %s\n", (int)sizeof(abBlob), pFileName);
		CloseHandle(hFile);
		return FALSE;
	}

	if (!ReadFile(hFile, abBlob, sizeof(abBlob), &cbBlob, 0))
	{
		DEBUG("Read %s error\n", pFileName);
		CloseHandle(hFile);
		return FALSE;
	}

	if (!NT_SUCCESS(status = BCryptImportKeyPair(m_hProv, NULL, pKeyType, &m_hKey, abBlob, cbBlob, 0)))
	{
		DEBUG("BCryptImportKeyPair returns 0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}

BOOL EZRSA::fnbExport(LPCWSTR pKeyType, PUCHAR pbBlob, ULONG cbBlob, PULONG pResult)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbData = 0;
	if (!NT_SUCCESS(status = BCryptExportKey(m_hKey, NULL, pKeyType, NULL, 0, &cbData, 0)))
	{
		DEBUG("BCryptExportKey#1 returns 0x%x\n", status);
		return FALSE;
	}

	if (pResult)
		*pResult = cbData;

	if (cbBlob < cbData)
		return FALSE;

	if (!NT_SUCCESS(status = BCryptExportKey(m_hKey, NULL, pKeyType, pbBlob, cbBlob, &cbBlob, 0)))
	{
		DEBUG("BCryptExportKey#2 returns 0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}

BOOL EZRSA::fnbExport(LPCWSTR pKeyType, LPCTSTR pFileName, EZRSA* pEncryptKey)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	UCHAR abBlob[4096];
	ULONG cbBlob = 0;
	UCHAR abBlock[256];
	ULONG cbData = 0;



	return TRUE;
}

BOOL EZRSA::fnbEncrypt(PUCHAR pbPlain, ULONG cbPlain, PUCHAR pbCipher, ULONG cbCipher, PULONG pcbResult)
{


	return TRUE;
}

BOOL EZRSA::fnbDecrypt(PUCHAR pbCipher, ULONG cbCipher, PUCHAR pbPlain, ULONG cbPlain, PULONG pcbResult)
{


	return TRUE;
}
