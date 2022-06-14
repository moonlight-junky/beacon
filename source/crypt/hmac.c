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
 * CryptHmacInit
 *
 * Purpose:
 *
 * Creates the key object for HMAC
 *
-*/
DEFINESEC(B) BOOL CryptHmacInit( PBEACON_INSTANCE Ins )
{
	if ( Ins->api.CryptAcquireContextA( &Ins->key[2].Provider, NULL, 0, PROV_RSA_SCHANNEL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
	{
		if ( Ins->api.CryptImportKey( Ins->key[2].Provider, Ins->key[2].Ptr, Ins->key[2].Len, 0, CRYPT_IPSEC_HMAC_KEY, &Ins->key[2].Key ) )
		{
			return TRUE;
		};
		Ins->api.CryptReleaseContext( Ins->key[2].Provider, 0 );
	};
	return FALSE;
};

/*-
 *
 * CryptHmacFree
 *
 * Purpose:
 *
 * Free's the associated keys for HMAC
 *
-*/
DEFINESEC(B) VOID CryptHmacFree( PBEACON_INSTANCE Ins )
{
	Ins->api.CryptDestroyKey( Ins->key[2].Key );
	Ins->api.CryptReleaseContext( Ins->key[2].Provider, 0 );
};

/*-
 *
 * CryptHmacHash
 *
 * Purpose:
 *
 * Hashes the input buffer with the 
 * provided key.
 *
-*/
DEFINESEC(B) BOOL CryptHmacHash( PBEACON_INSTANCE Ins, PVOID InBuf, ULONG InLen, PVOID OutBuf )
{
	BOOL       Resb = FALSE;
	HMAC_INFO  Hmac = { .HashAlgid = CALG_SHA_256, 0x0 };
	HCRYPTHASH Hash = 0;
	ULONG      Size = 32;

	if ( Ins->api.CryptCreateHash( Ins->key[2].Provider, CALG_HMAC, Ins->key[2].Key, 0, &Hash ) )
	{
		if ( Ins->api.CryptSetHashParam( Hash, HP_HMAC_INFO, CPTR( &Hmac ), 0 ) )
		{
			if ( Ins->api.CryptHashData( Hash, InBuf, InLen, 0 ) )
			{
				Resb = Ins->api.CryptGetHashParam(
						Hash,
						HP_HASHVAL,
						OutBuf,
						&Size,
						0
						);
			};
		};
		Ins->api.CryptDestroyHash( Hash );
	};
	return Resb;
};
