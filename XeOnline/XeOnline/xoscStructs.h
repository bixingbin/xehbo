#ifndef __XOSCSTRUCTS_H
#define __XOSCSTRUCTS_H

// structs for 17150 hv stuff (including xosc)
#define DVD_INQUIRY_RESPONSE_SIZE	0x24

#define XOSC_DVD_INQUIRY_FLAG		0x1
#define XOSC_XEIKA_INQUIRY_FLAG		0x2
#define XOSC_MEDIA_INQUIRY_FLAG		0x4
#define XOSC_SECURITY_INQUIRY_FLAG	0x8
#define	XOSC_STORAGE_INQUIRY_FLAG	0x10
#define XOSC_SERIAL_INQUIRY_FLAG	0x20
#define XOSC_MEDIA_INQUIRY_FLAG		0x40
#define XOSC_HDD_INQUIRY_FLAG		0x80
#define XOSC_PCI_INQUIRY_FLAG		0x100

typedef enum _MEDIA_TYPE {
	Unknown = 0x00,
	F5_1Pt2_512 = 0x01,
	F3_1Pt44_512 = 0x02,
	F3_2Pt88_512 = 0x03,
	F3_20Pt8_512 = 0x04,
	F3_720_512 = 0x05,
	F5_360_512 = 0x06,
	F5_320_512 = 0x07,
	F5_320_1024 = 0x08,
	F5_180_512 = 0x09,
	F5_160_512 = 0x0a,
	RemovableMedia = 0x0b,
	FixedMedia = 0x0c,
	F3_120M_512 = 0x0d,
	F3_640_512 = 0x0e,
	F5_640_512 = 0x0f,
	F5_720_512 = 0x10,
	F3_1Pt2_512 = 0x11,
	F3_1Pt23_1024 = 0x12,
	F5_1Pt23_1024 = 0x13,
	F3_128Mb_512 = 0x14,
	F3_230Mb_512 = 0x15,
	F8_256_128 = 0x16,
	F3_200Mb_512 = 0x17,
	F3_240M_512 = 0x18,
	F3_32M_512 = 0x19
} MEDIA_TYPE;


typedef struct _DISK_GEOMETRY {
	LARGE_INTEGER Cylinders;
	MEDIA_TYPE    MediaType;
	DWORD         TracksPerCylinder;
	DWORD         SectorsPerTrack;
	DWORD         BytesPerSector;
} DISK_GEOMETRY;

// needs pragma pack
#pragma pack(push, 1)
typedef struct _RESPONSE_DATA {
	DWORD dwResult; // 0
	WORD verMaj; // 4 = 9
	WORD verMin; // 6 = 2
	QWORD flags; // 8
	NTSTATUS DvdInqResp; // 0x10
	NTSTATUS XeikaInqResp; // 0x14
	NTSTATUS ExecIdResp; // 0x18
	NTSTATUS HvIdCacheDataResp; // 0x1C
	NTSTATUS MediaInfoResp; // 0x20
	DWORD MediaInfodwUnk1; // 0x24
	DWORD MediaInfodwUnk2; // 0x28
	DWORD MediaInfoAbUnk; // 0x2C
	DWORD MediaInfoPad5; // 0x30
	DWORD HardwareMaskTemplate; // 0x34 = this is hardcoded in xosc and filled in when PCI hardware revision query occurs
	XEX_EXECUTION_ID xid; // 0x38 sz 0x18
	BYTE hvCpuKeyHash[0x10]; // 0x50
	BYTE xexHashing[0x10]; // 0x60
	BYTE zeroEncryptedConsoleType[0x10]; // 0x70
	DWORD DvdXeikaPhaseLevel; // 0x80
	DWORD dwMediaType; // 0x84
	DWORD dwTitleId; // 0x88
	BYTE DvdPfiInfo[0x11]; // 0x8C
	BYTE DvdDmiMediaSerial[0x20]; // 0x9D
	BYTE DvdMediaId1[0x10]; // 0xBD
	BYTE abPad[3];			// BYTE tempPad[]; // 0xCD
	QWORD DvdDmi10Data; // 0xD0
	DISK_GEOMETRY DvdGeometry; // 0xD8
	BYTE DvdMediaId2[0x10]; // 0xE0
	BYTE DvdInqRespData[DVD_INQUIRY_RESPONSE_SIZE]; // 0xF0
	BYTE XeikaInqData[DVD_INQUIRY_RESPONSE_SIZE]; // 0x114
	BYTE ConsoleSerial[0xC]; // 0x138
	WORD wPad;				// BYTE tempPad[]; // 0x144
	WORD hvHeaderFlags; // 0x146
	WORD hvUnrestrictedPrivs; // 0x148
	WORD kvOddFeatures; // 0x14A
	DWORD hvUnknown; // 0x14C
	DWORD kvPolicyFlashSize; // 0x150
	DWORD kvRestrictedStatus; // 0x154
	DWORD hvKeyStatus; // 0x158
	DWORD dwPad1;			// BYTE tempPad[]; // 0x15C
	QWORD secDataDvdBootFailures; // 0x160 < not sure why they expand the lowpart into quad
	DWORD secDataFuseBlowFailures; // 0x168
	DWORD dwPad2; // 0x16C
	QWORD HardwareMask; // 0x170 calculated from pci info on device 2
	DWORD secDataDvdAuthExFailures; // 0x178
	DWORD secDataDvdAuthExTimeouts;		// BYTE tempPad[]; // 0x17C
	QWORD kvRestrictedPrivs; // 0x180
	QWORD hvSecurityDetected; // 0x188
	QWORD hvSecurityActivated; // 0x190
	QWORD hvProtectedFlags; // 0x198
	QWORD ConsoleId[6]; // 0x1A0
	DWORD XboxHardwareInfoFlags; // 0x1D0
		// 0x1D4 - 0x21C HDD related info
	BYTE HddSerialNumber[0x14]; // 0x1D4
	BYTE HddFirmwareRevision[0x8]; // 0x1E8
	BYTE HddModelNumber[0x28]; // 0x1F0
	DWORD HddUserAddressableSectors; // 0x218
	BYTE unkMediaInfo[0x80]; // 0x21C
	QWORD DvdUnkp1; // 0x29C
	DWORD MediaInfoUnkp3; // 0x2A4
	DWORD Mu0Au; // 0x2A8 "\\Device\\Mu0\\" allocationUnits.lowpart
	DWORD Mu1Au; // 0x2Ac "\\Device\\Mu1\\" allocationUnits.lowpart
	DWORD SfcAu; // 0x2B0 "\\Device\\BuiltInMuSfc" allocationUnits.lowpart
	DWORD IntMuAu; // 0x2B4 "\\Device\\BuiltInMuUsb\\Storage\\" allocationUnits.lowpart
	DWORD UsbMu0; // 0x2B8 "\\Device\\Mass0PartitionFile\\Storage\\" allocationUnits.lowpart
	DWORD UsbMu1; // 0x2BC "\\Device\\Mass1PartitionFile\\Storage\\" allocationUnits.lowpart
	DWORD UsbMu2; // 0x2C0 "\\Device\\Mass2PartitionFile\\Storage\\" allocationUnits.lowpart
	DWORD crlVersion; // 0x2C4
	QWORD Layer0PfiSectors; // 0x2C8
	QWORD Layer1PfiSectors; // 0x2D0
	DWORD respMagic; // 0x2D8 0x5F534750 '_SGP'
	DWORD dwFinalPad; // 0x2DC
} RESPONSE_DATA, *PRESPONSE_DATA; // total size 0x2E0
C_ASSERT(sizeof(RESPONSE_DATA) == 0x2E0);
#pragma pack(pop)

typedef struct _SECDATA_BLOB_CACHECOPY{ // 8E038700 virt 6401F18700 phy
	DWORD dwCompatReserved; // 0x0
	DWORD dwDvdBootFailures; // 0x4
	DWORD dwFuseBlowFailures; // 0x8
	DWORD dwDvdAuthExFailures; // 0xC
	DWORD dwDvdAuthExTimeouts; // 0x10
	//Large_INTEGER cDvdDetectionError; // 0
	//LARGE_INTEGER cLockSystemUpdate; // 8
	//DWORD dwUnk; // 0x10
	BYTE pad2[0x6C]; // 0x14
} SECDATA_BLOB_CACHECOPY, *PSECDATA_BLOB_CACHECOPY;
C_ASSERT(sizeof(SECDATA_BLOB_CACHECOPY) == 0x80);

typedef struct _CONSOLE_ID_HASH_CACHE { // 8E038000 virt 6401F18000phy
	BYTE abHash[0x14]; // 0 - sha1 hash of the following 0x3E0 bytes, after counter is updated, neg1 set to 0xFFFFFFFF and zero set to 0x0
	DWORD dwHashUpdateCount; // 0x14
	BYTE pad1[8]; // 0x18
	union {
		BYTE consoleId[0x8]; // 0x20
		QWORD consoleIdAsQw;
	}cId;
	DWORD neg1; // 0x28
	DWORD zero; // 0x2C
	BYTE pad2[0x3D0]; // 0x30
} CONSOLE_ID_HASH_CACHE, *PCONSOLE_ID_HASH_CACHE; // size 0x400
C_ASSERT(sizeof(CONSOLE_ID_HASH_CACHE) == 0x400);

#pragma pack(push, 1)
typedef struct _MEDIA_INFO_CACHE{ // 8E038780 virt 6401f18780 phy
	BYTE abSha[0x14];// 0 hash of following 0x8C bytes
	DWORD dwUnk1; // 0x14
	DWORD dwUnk2; // 0x18
	union{
		BYTE abUnk[4]; // 0x1C
		DWORD abUnkAsDword;
	} bUnk;
	BYTE abPfi[0x10]; // 0x20 PFI from dvd
	BYTE pad2[0x4]; // 0x30
	DWORD HvLayer0PfiSectors; // 0x34 seems to be calculated from PFI info
	DWORD HvLayer1PfiSectors; // 0x38
	BYTE pad3[0x4]; // 0x3C
	BYTE DmiMediaSerial[0x10]; // 0x40 < at least following 4 bytes are relevant
	BYTE pad4[0x10]; // 0x50 could be info following serial from DMI
	BYTE MediaId1[0x10]; // 0x60
	QWORD Dmi10Data; // 0x70 comes from DMI at offset 0x10
	DISK_GEOMETRY dvdGeom; // 0x78 sz 0x8
	BYTE MediaId2[0x10]; // 0x80
	DWORD pad5; // 0x90 < relevant?
	QWORD dwUnkp1; // 0x94 < relevant?
	DWORD dwUnkp3; // 0x9C
} MEDIA_INFO_CACHE, *PMEDIA_INFO_CACHE;
C_ASSERT(sizeof(MEDIA_INFO_CACHE) == 0xA0);
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _SECURITY_INFO_CACHE { // 8E038600 virt 6401f18600 phy
	WORD headerFlags; // 0
	WORD unrestrictedPrivs; // 2 seems to be 0xFF on unrestricted machines, affected by kv restricted privs flags
	WORD kvOddFeatures; // 4
	BYTE abUnk1[0xA]; // 6
	DWORD keyStatus; // 0x10
	DWORD hvRestrictedStatus; // 0x14 0x70000 if unrestrictedPrivs above is not 0x102, if it is this val is based on keystatus
	DWORD kvPolicyFlashSize; // 0x18 from kv, only on machines with bootloaders that flag kv signature required
	DWORD dwUnk1; // 0x1C
	DWORD kvPolicyBuiltInMuSize; // 0x20 from kv, only on machines with bootloaders that flag kv signature required
	BYTE abUnk2[0xC]; // 0x24
	QWORD kvRestrictedPrivs; // 0x30
	QWORD secdataSecurityDetected; // 0x38 copied here from secdata when its loaded
	QWORD secdataSecurityActivated; // 0x40 copied here from secdata when its loaded
	SHORT sUnk1; // 0x48
	SHORT sUnk2; // 0x4A
	BYTE abUnk3[0x2C]; // 0x4C
	QWORD hvProtectedFlagsCopy; // 0x78 6401f18678
	BYTE hvMediaInfoUnk80[0x80]; // 0x80
} SECURITY_INFO_CACHE, *PSECURITY_INFO_CACHE;

// hacked up a little from the official union
typedef struct _DYNAMIC_REVOCATION_LIST_STATIC { // 0x8E000000 virt
	CERTIFICATE_REVOCATION_LIST_HEADER RevocationList; // 0x0 sz:0x150
	CERTIFICATE_REVOCATION_DATA DataHeader; // 0x150 sz 0xC
	BYTE DataBuf[0x7EA4]; // 0x0 sz:0x8000
} YNAMIC_REVOCATION_LIST_STATIC, *PDYNAMIC_REVOCATION_LIST_STATIC; // size 32768
C_ASSERT(sizeof(DYNAMIC_REVOCATION_LIST_STATIC) == 0x8000);

typedef struct _HV_KEY_HEADER_INFO { // 8E03AA30 virt 6401f1AA30 phy
	BYTE HvCpuKeyShaCache[0x10]; // 0
	BYTE HvKvHmacShaCache[0x10]; // 0x10
	BYTE HvZeroEncryptedWithConsoleType[0x10]; // 0x20 a 0x0 buffer encrypted with a key built from console type in fuses
	BLDR_FLASH HvFlashHeaderCache;
} HV_KEY_HEADER_INFO, *PHV_KEY_HEADER_INFO;
C_ASSERT(sizeof(HV_KEY_HEADER_INFO) == 0xB0);

static PSECDATA_BLOB_CACHECOPY HvSecDataPartCopy = (PSECDATA_BLOB_CACHECOPY)(0x8E038700);
static PCONSOLE_ID_HASH_CACHE HvIdHashCache = (PCONSOLE_ID_HASH_CACHE)(0x8E038000);
static PMEDIA_INFO_CACHE HvMediaInfoCache = (PMEDIA_INFO_CACHE)(0x8E038780);
static PHDD_SECURITY_BLOB HvHddSecurityBlobCache = (PHDD_SECURITY_BLOB)(0x8E038400);
static PSECURITY_INFO_CACHE HvSecurityInfoCache = (PSECURITY_INFO_CACHE)(0x8E038600);
static PDYNAMIC_REVOCATION_LIST_STATIC HvCrlCache = (PDYNAMIC_REVOCATION_LIST_STATIC)(0x8E000000);
static PHV_KEY_HEADER_INFO HvKeyInfo = (PHV_KEY_HEADER_INFO)(0x8E03AA30); // 0x30 bytes of hashes followed by flash header cache

typedef NTSTATUS(*XOSCFUNCALL)(void* r3, void* r4, void* r5, RESPONSE_DATA* resp);
#define XOSC_FUN_NUMBER		5

#endif //__XOSCSTRUCTS_H