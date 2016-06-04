#include "stdafx.h"

const BYTE masterKey[272] = {
	0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xDD, 0x5F, 0x49, 0x6F, 0x99, 0x4D, 0x37, 0xBB, 0xE4, 0x5B, 0x98, 0xF2, 0x5D, 0xA6, 0xB8, 0x43,
	0xBE, 0xD3, 0x10, 0xFD, 0x3C, 0xA4, 0xD4, 0xAC, 0xE6, 0x92, 0x3A, 0x79, 0xDB, 0x3B, 0x63, 0xAF,
	0x38, 0xCD, 0xA0, 0xE5, 0x85, 0x72, 0x01, 0xF9, 0x0E, 0x5F, 0x5A, 0x5B, 0x08, 0x4B, 0xAD, 0xE2,
	0xA0, 0x2A, 0x42, 0x33, 0x85, 0x34, 0x53, 0x83, 0x1E, 0xE5, 0x5B, 0x8F, 0xBF, 0x35, 0x8E, 0x63,
	0xD8, 0x28, 0x8C, 0xFF, 0x03, 0xDC, 0xC4, 0x35, 0x02, 0xE4, 0x0D, 0x1A, 0xC1, 0x36, 0x9F, 0xBB,
	0x90, 0xED, 0xDE, 0x4E, 0xEC, 0x86, 0x10, 0x3F, 0xE4, 0x1F, 0xFD, 0x96, 0xD9, 0x3A, 0x78, 0x25,
	0x38, 0xE1, 0xD3, 0x8B, 0x1F, 0x96, 0xBD, 0x84, 0xF6, 0x5E, 0x2A, 0x56, 0xBA, 0xD0, 0xA8, 0x24,
	0xE5, 0x02, 0x8F, 0x3C, 0xA1, 0x9A, 0xEB, 0x93, 0x59, 0xD7, 0x1B, 0x99, 0xDA, 0xC4, 0xDF, 0x7B,
	0xD0, 0xC1, 0x9A, 0x12, 0xCC, 0x3A, 0x17, 0xBF, 0x6E, 0x4D, 0x78, 0x87, 0xD4, 0x2A, 0x7F, 0x6B,
	0x9E, 0x2F, 0xCD, 0x8D, 0x4E, 0xF5, 0xCE, 0xC2, 0xA0, 0x5A, 0xA3, 0x0F, 0x9F, 0xAD, 0xFE, 0x12,
	0x65, 0x74, 0x20, 0x6F, 0xF2, 0x5C, 0x52, 0xE4, 0xB0, 0xC1, 0x3C, 0x25, 0x0D, 0xAE, 0xD1, 0x82,
	0x7C, 0x60, 0xD7, 0x44, 0xE5, 0xCD, 0x8B, 0xEA, 0x6C, 0x80, 0xB5, 0x1B, 0x7A, 0x0C, 0x02, 0xCE,
	0x0C, 0x24, 0x51, 0x3D, 0x39, 0x36, 0x4A, 0x3F, 0xD3, 0x12, 0xCF, 0x83, 0x8D, 0x81, 0x56, 0x00,
	0xB4, 0x64, 0x79, 0x86, 0xEA, 0xEC, 0xB6, 0xDE, 0x8A, 0x35, 0x7B, 0xAB, 0x35, 0x4E, 0xBB, 0x87,
	0xEA, 0x1D, 0x47, 0x8C, 0xE1, 0xF3, 0x90, 0x13, 0x27, 0x97, 0x55, 0x82, 0x07, 0xF2, 0xF3, 0xAA,
	0xF9, 0x53, 0x47, 0x8F, 0x74, 0xA3, 0x8E, 0x7B, 0xAE, 0xB8, 0xFC, 0x77, 0xCB, 0xFB, 0xAB, 0x8A
};

namespace xbox {
	namespace keyvault {
		namespace data {
			KEY_VAULT buffer;
			DWORD updSeqFlags;
			DWORD cTypeFlags;
			DWORD hardwareFlags;
			DWORD hvStatusFlags = 0x23289D3;
			DWORD bldrFlags = 0xD83E;
			BYTE consoleType;
			BYTE cpuKey[0x10];
			BYTE cpuKeyDigest[0x14];
			BYTE keyvaultDigest[0x14];
			BYTE proccessDigest[0x14];
		}

		BYTE char2byte(char input)
		{
			if (input >= '0' && input <= '9')
				return input - '0';
			if (input >= 'A' && input <= 'F')
				return input - 'A' + 10;
			if (input >= 'a' && input <= 'f')
				return input - 'a' + 10;
			return 0;
		}

		BOOL XeKeysPkcs1Verify(const BYTE* pbHash, const BYTE* pbSig, XECRYPT_RSA* pRsa)
		{
			BYTE scratch[256];
			DWORD val = pRsa->cqw << 3;
			if (val <= 0x200)
			{
				XeCryptBnQw_SwapDwQwLeBe((QWORD*)pbSig, (QWORD*)scratch, val >> 3);
				if (XeCryptBnQwNeRsaPubCrypt((QWORD*)scratch, (QWORD*)scratch, pRsa) == 0) return FALSE;
				XeCryptBnQw_SwapDwQwLeBe((QWORD*)scratch, (QWORD*)scratch, val >> 3);
				return XeCryptBnDwLePkcs1Verify((const PBYTE)pbHash, scratch, val);
			}
			else return FALSE;
		}

		HRESULT setupSpecialValues(DWORD updSeq)
		{
			BOOL fcrtRequired = (xbox::keyvault::data::buffer.OddFeatures & ODD_POLICY_FLAG_CHECK_FIRMWARE) != 0;
			BYTE moboSerialByte = (((char2byte(data::buffer.ConsoleCertificate.ConsolePartNumber[2]) << 4) & 0xF0) | ((char2byte(data::buffer.ConsoleCertificate.ConsolePartNumber[3]) & 0x0F)));

			if (fcrtRequired)
			{
				data::hvStatusFlags |= 0x1000000;
				//data::bldrFlags = 0xD81E;
			}

			if (moboSerialByte < 0x10)
			{
				data::consoleType = 0;
				data::cTypeFlags = 0x010B0FFB;
			}
			else if (moboSerialByte < 0x14)
			{
				data::consoleType = 1;
				data::cTypeFlags = 0x010B0524;
			}
			else if (moboSerialByte < 0x18)
			{
				data::consoleType = 2;
				data::cTypeFlags = 0x010C0AD8;
			}
			else if (moboSerialByte < 0x52)
			{
				data::consoleType = 3;
				data::cTypeFlags = 0x010C0AD0;
			}
			else if (moboSerialByte < 0x58)
			{
				data::consoleType = 4;
				data::cTypeFlags = 0x0304000D;
			}
			else
			{
				data::consoleType = 5;
				data::cTypeFlags = 0x0304000E;
			}

			data::hardwareFlags = (XboxHardwareInfo->Flags & 0x0FFFFFFF) | ((data::consoleType & 0xF) << 28);
			data::hardwareFlags = data::hardwareFlags &~0x20;
			data::updSeqFlags = updSeq;

			// setup kv console data
			xbox::hypervisor::pokeDword(0x4, data::bldrFlags);
			xbox::hypervisor::pokeDword(0x14, data::updSeqFlags);
			xbox::hypervisor::pokeBytes(0x20, data::cpuKey, 0x10);
			xbox::hypervisor::pokeDword(0x30, data::hvStatusFlags);
			xbox::hypervisor::pokeDword(0x74, data::cTypeFlags);

			// disable chall decryption & fix NiNJA fuckup for xebuild images
			//xbox::hypervisor::pokeDword(global::isDevkit ? 0x60B0 : 0x6148, 0x60000000);
			//xbox::hypervisor::pokeDword(global::isDevkit ? 0x60E4 : 0x617C, 0x38600001);
			//if (global::isDevkit) xbox::hypervisor::pokeDword(0x5FF8, 0x48000010);
			//if (!global::isDevkit) *(DWORD*)0x80109574 = 0x44000002;

			// setup our custom challenge
			//if (!XGetModuleSection(global::modules::client, "HVC", &global::challenge::bufferAddress, &global::challenge::bufferSize))
			//	return E_FAIL;

			return S_OK;
		}

		HRESULT initialize()
		{
			MemoryBuffer mbKv;
			MemoryBuffer mbCpu;

			if (!xbox::utilities::readFile(FILE_PATH_KV, mbKv))
				return E_FAIL;

			if (mbKv.GetDataLength() != 0x4000)
				return E_FAIL;

			if (!xbox::utilities::readFile(FILE_PATH_CPUKEY, mbCpu))
				return E_FAIL;

			if (mbCpu.GetDataLength() != 0x10)
				return E_FAIL;

			memcpy(data::cpuKey, mbCpu.GetData(), 0x10);
			XeCryptSha(data::cpuKey, 0x10, NULL, NULL, NULL, NULL, data::cpuKeyDigest, XECRYPT_SHA_DIGEST_SIZE);

			QWORD kvAddress = xbox::hypervisor::peekQword(global::isDevkit ? 0x00000002000162E0 : 0x0000000200016240);

			memcpy(&data::buffer, mbKv.GetData(), 0x4000);
			ZeroMemory(data::buffer.RoamableObfuscationKey, 0x10);

			XECRYPT_HMACSHA_STATE hmacSha;
			XeCryptHmacShaInit(&hmacSha, data::cpuKey, 0x10);
			XeCryptHmacShaUpdate(&hmacSha, (PBYTE)&data::buffer.OddFeatures, 0xD4);
			XeCryptHmacShaUpdate(&hmacSha, data::buffer.DvdKey, 0x1CF8);
			XeCryptHmacShaUpdate(&hmacSha, data::buffer.CardeaCertificate, 0x2108);
			XeCryptHmacShaFinal(&hmacSha, data::keyvaultDigest, XECRYPT_SHA_DIGEST_SIZE);

			if (!XeKeysPkcs1Verify(data::keyvaultDigest, data::buffer.KeyVaultSignature, (XECRYPT_RSA*)masterKey))
				xbox::utilities::log("The cpu key provided is not for this keyvault.");

			xbox::utilities::setMemory((PVOID)0x8E03A000, &data::buffer.ConsoleCertificate, 0x1A8);
			if (global::isDevkit) xbox::utilities::setMemory((BYTE*)(GetPointer(0x81D6B198) + 0x30BC), &data::buffer.ConsoleCertificate, 0x1A8);
			xbox::utilities::setMemory((PVOID)0x8E038020, &data::buffer.ConsoleCertificate.ConsoleId.abData, 5);

			BYTE newHash[XECRYPT_SHA_DIGEST_SIZE];
			XeCryptSha((BYTE*)0x8E038014, 0x3EC, NULL, NULL, NULL, NULL, newHash, XECRYPT_SHA_DIGEST_SIZE);
			xbox::utilities::setMemory((PVOID)0x8E038000, newHash, XECRYPT_SHA_DIGEST_SIZE);

			xbox::hypervisor::peekBytes(kvAddress + 0xD0, &data::buffer.ConsoleObfuscationKey, 0x40);
			xbox::hypervisor::pokeBytes(kvAddress, &data::buffer, 0x4000);
			if(!global::isDevkit) XamCacheReset(XAM_CACHE_TICKETS);

			BYTE currentMacAddress[6];
			BYTE spoofedMacAddress[6] = {
				0xFF, 0xFF, 0xFF,
				data::buffer.ConsoleCertificate.ConsoleId.asBits.MacIndex3,
				data::buffer.ConsoleCertificate.ConsoleId.asBits.MacIndex4,
				data::buffer.ConsoleCertificate.ConsoleId.asBits.MacIndex5
			};

			if ((XboxHardwareInfo->Flags & 0xF0000000) > 0x40000000)
			{
				spoofedMacAddress[0] = 0x7C;
				spoofedMacAddress[1] = 0xED;
				spoofedMacAddress[2] = 0x8D;
			}
			else
			{
				spoofedMacAddress[0] = 0x00;
				spoofedMacAddress[1] = 0x22;
				spoofedMacAddress[2] = 0x48;
			}

			if (NT_SUCCESS(ExGetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, currentMacAddress, 6, NULL)))
				if (memcmp(currentMacAddress, spoofedMacAddress, 6) != 0)
					if (NT_SUCCESS(ExSetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, spoofedMacAddress, 6)))
					{
						XamCacheReset(XAM_CACHE_ALL);
						HalReturnToFirmware(HalFatalErrorRebootRoutine);
					}

			DWORD temp = 0;
			XeCryptSha(spoofedMacAddress, 6, NULL, NULL, NULL, NULL, (BYTE*)&temp, 4);
			
			if (setupSpecialValues(temp & ~0xFF) != S_OK)
				return E_FAIL;

			return S_OK;
		}
	}
}