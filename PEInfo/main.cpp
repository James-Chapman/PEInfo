
#pragma warning(disable : 4996)

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <iostream>
#include <fstream>

#include "cereal/archives/json.hpp"
#include "cereal/cereal.hpp"

#include "common_defs.h"
#include "FileIO.hpp"
#include "PEFile.hpp"

using namespace uplinkzero;

int CollectPEHeaders(BYTE * pBuffer)
{
	BYTE * pSignatureLocation = pBuffer + 0x3c;
	BYTE * pPEHeader = pBuffer + *pSignatureLocation;
	if (pPEHeader[0] == 0x50 && // P
		pPEHeader[1] == 0x45 && // E
		pPEHeader[2] == 0x0 &&
		pPEHeader[3] == 0x0)
	{
		BYTE * pCOFFHeader = pPEHeader + 4;
		printf("pBuffer:     %p = 0x%x\n", pBuffer, *pBuffer);
		printf("pPEHeader:   %p = 0x%x\n", pPEHeader, *pPEHeader);
		printf("pCOFFHeader: %p = 0x%x\n", pCOFFHeader, *pCOFFHeader);

		PEFile peFile;
		
		COFF_Header coff;
		coff.pMachine = reinterpret_cast<WORD *>(pCOFFHeader + 0);
		coff.pNumberOfSections = reinterpret_cast<WORD *>(pCOFFHeader + 2);
		coff.pTimeDateStamp = reinterpret_cast<DWORD *>(pCOFFHeader + 4);
		coff.pPointerToSymbolTable = reinterpret_cast<DWORD *>(pCOFFHeader + 8);
		coff.pNumberOfSymbols = reinterpret_cast<DWORD *>(pCOFFHeader + 12);
		coff.pSizeOfOptionalHeader = reinterpret_cast<WORD *>(pCOFFHeader + 16);
		coff.pCharacteristics = reinterpret_cast<WORD *>(pCOFFHeader + 18);

		coff.Machine = *(reinterpret_cast<WORD *>(pCOFFHeader + 0));
		coff.NumberOfSections = *(reinterpret_cast<WORD *>(pCOFFHeader + 2));
		coff.TimeDateStamp = *(reinterpret_cast<DWORD *>(pCOFFHeader + 4));
		coff.PointerToSymbolTable = *(reinterpret_cast<DWORD *>(pCOFFHeader + 8));
		coff.NumberOfSymbols = *(reinterpret_cast<DWORD *>(pCOFFHeader + 12));
		coff.SizeOfOptionalHeader = *(reinterpret_cast<WORD *>(pCOFFHeader + 16));
		coff.Characteristics = *(reinterpret_cast<WORD *>(pCOFFHeader + 18));

		std::ofstream os("headers.json", std::ios::binary);
		cereal::JSONOutputArchive archive(os);
		cereal::JSONOutputArchive archive_cout(std::cout);
		coff.serialize(archive);
		coff.serialize(archive_cout);

		//printf("Machine:              offset: 0x%x value: 0x%x\n", reinterpret_cast<BYTE *>(coff.pMachine) - pBuffer, coff.Machine);
		//printf("NumberOfSections:     offset: 0x%x value: 0x%x\n", reinterpret_cast<BYTE *>(coff.pNumberOfSections) - pBuffer, coff.NumberOfSections);
		//printf("TimeDateStamp:        offset: 0x%x value: 0x%x\n", reinterpret_cast<BYTE *>(coff.pTimeDateStamp) - pBuffer, coff.TimeDateStamp);
		//printf("PointerToSymbolTable: offset: 0x%x value: 0x%x\n", reinterpret_cast<BYTE *>(coff.pPointerToSymbolTable) - pBuffer, coff.PointerToSymbolTable);
		//printf("NumberOfSymbols:      offset: 0x%x value: 0x%x\n", reinterpret_cast<BYTE *>(coff.pNumberOfSymbols) - pBuffer, coff.NumberOfSymbols);
		//printf("SizeOfOptionalHeader: offset: 0x%x value: 0x%x\n", reinterpret_cast<BYTE *>(coff.pSizeOfOptionalHeader) - pBuffer, coff.SizeOfOptionalHeader);
		//printf("Characteristics:      offset: 0x%x value: 0x%x\n", reinterpret_cast<BYTE *>(coff.pCharacteristics) - pBuffer, coff.Characteristics);

	}
	return 0;
}

int main(int argc, char * argv[])
{
	char * fileName = argv[1];
	auto fio = Uplinkzero::FileIO(fileName);
	auto sz = fio.GetFileSize();

	BYTE * pBuffer = reinterpret_cast<BYTE *>(malloc(sz + 1));
	pBuffer[sz + 1] = '\0';
	fio.ReadBlock(pBuffer, sz);

	CollectPEHeaders(pBuffer);
	
	//printf("COFF location: %p = 0x%x\n", coff_location, *coff_location);
	//printf("Machine: 0x%x\n", reinterpret_cast<WORD>(buf + *coff_location + 4 + 0));
	//printf("NumberOfSections: 0x%x\n", reinterpret_cast<WORD>(buf + *coff_location + 4 + 2));
	//printf("TimeDateStamp: 0x%x\n", reinterpret_cast<DWORD>(buf + *coff_location + 4 + 4));
	//printf("PointerToSymbolTable: 0x%x\n", reinterpret_cast<DWORD>(buf + *coff_location + 4 + 8));
	//printf("NumberOfSymbols: 0x%x\n", reinterpret_cast<DWORD>(buf + *coff_location + 4 + 12));
	//printf("SizeOfOptionalHeader: 0x%x\n", reinterpret_cast<WORD>(buf + *coff_location + 4 + 16));
	//printf("Characteristics: 0x%x\n", reinterpret_cast<WORD>(buf + *coff_location + 4 + 18));

	return 0;
}



