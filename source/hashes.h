/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#pragma once

#define H_NTDLL					0x1edab0ed	
#define H_KERNEL32				0x6ddb9555

#define H_SLEEPEX				0xaf312e3b

#define H_WCSLEN				0xd7bb0d31	
#define H_WCSRCHR				0xcf1ff4a1
#define H_WCSTOMBS				0xb34961d7

#define H_GETACP				0xb28d1179
#define H_GETOEMCP				0x8b15bfb9
#define H_LOCALLOCK				0x32064bd9
#define H_LOCALFREE				0x32030e92
#define H_LOCALSIZE				0x320a0beb
#define H_LOCALALLOC				0x72073b5b
#define H_LOCALUNLOCK				0xe1ba049c
#define H_LOCALREALLOC				0x1c44e892

#define H_CLOSEHANDLE				0xfdb928e7
#define H_FREELIBRARY				0x4ad9b11c
#define H_RTLRANDOMEX				0x7f1224f5
#define H_LOADLIBRARYA				0xb7072fdb
#define H_GETTICKCOUNT				0xa28ae999
#define H_CRYPTDECRYPT				0x4c86df12
#define H_CRYPTENCRYPT				0xae7f897c
#define H_CRYPTHASHDATA				0x7f12f355
#define H_CRYPTGENRANDOM			0x343d3c72
#define H_CRYPTIMPORTKEY			0x1370cc7b
#define H_CRYPTCREATEHASH			0x56cedcef
#define H_CRYPTDESTROYKEY			0x0ec7f6aa
#define H_OPENTHREADTOKEN			0xe249d070
#define H_OPENPROCESSTOKEN			0xd9f566f7
#define H_CRYPTSETKEYPARAM			0x0c57bc7d
#define H_CRYPTDESTROYHASH			0xe7c51545
#define H_GETCOMPUTERNAMEA			0x8c52da36
#define H_CRYPTSETHASHPARAM			0xa9525838
#define H_CRYPTGETHASHPARAM			0x5de9f7ac
#define H_LOOKUPACCOUNTSIDA			0xd51fdf8d
#define H_CRYPTRELEASECONTEXT			0x674798fd
#define H_CRYPTDECODEOBJECTEX			0x35691aef
#define H_GETCURRENTPROCESSID			0x0917ded4
#define H_GETTOKENINFORMATION			0x10357d2c
#define H_CRYPTACQUIRECONTEXTA			0xc4e81a47
#define H_CRYPTIMPORTPUBLICKEYINFO		0x28b94686
#define H_DNSWRITEQUESTIONTOBUFFER_UTF8		0x8daca0d0
#define H_DNSEXTRACTRECORDSFROMMESSAGE_UTF8	0x300c2cf6

#define H_RECV					0x7c8b3515
#define H_SEND					0x7c8bc2cf
#define H_WSASOCKETA				0x08a4d8fa
#define H_WSACONNECT				0x39c9bd7a
#define H_WSACLEANUP				0x32206eb8
#define H_WSASTARTUP				0x142e89c3
#define H_CLOSESOCKET				0x185953a4
