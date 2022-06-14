/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#include "common.h"

/*-
 * 
 * Sha256Sum
 *
 * Purpose:
 *
 * Calculates the SHA-256 sum of an input
 * string.
 *
-*/
DEFINESEC(B) PVOID Sha256Sum( PBEACON_INSTANCE Ins, PVOID Buf, ULONG Len )
{
	DWORD      Res = 1;
	PVOID      Sha = 0;
	DWORD      Exp = 4;
	DWORD      Siz = 0;
	HCRYPTHASH Hsh = 0;
	HCRYPTPROV Prv = 0;

	if ( Ins->api.CryptAcquireContextA( &Prv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
	{
		if ( Ins->api.CryptCreateHash( Prv, CALG_SHA_256, 0, 0, &Hsh ) )
		{
			if ( Ins->api.CryptHashData( Hsh, Buf, Len, 0 ) )
			{
				if ( Ins->api.CryptGetHashParam( Hsh, HP_HASHSIZE, CPTR( &Siz ), &Exp, 0 ) )
				{
					if ((Sha = Ins->api.LocalAlloc( LPTR, Siz )))
					{
						if ( Ins->api.CryptGetHashParam( Hsh, HP_HASHVAL, Sha, &Siz, 0 ) )
						{
							Res = 0;
						};
					};
				};
			};
			Ins->api.CryptDestroyHash( Hsh );
		};
		Ins->api.CryptReleaseContext( Prv, 0 );
	};

	return Res != 1 ? 
	       Sha : Ins->api.LocalFree( Sha );
};
