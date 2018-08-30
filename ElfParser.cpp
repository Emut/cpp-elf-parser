#include "ElfParser.h"
#include "EndianReader.hpp"
#include <stdio.h>
#include <string.h>


bool ElfParser::ParseHeader(char* cpFileName, ElfParser::tsELFHeaderInfo* stpResult)
{
	FILE* filep = fopen(cpFileName, "rb");
	if(filep == NULL)
	{
		printf("\nCan not open %s!", cpFileName);
		return false;
	}
	fseek (filep, 0, SEEK_END);   // non-portable
    int nFileSize = ftell (filep);
    rewind(filep);

    unsigned char* ucpBuffer = new unsigned char[nFileSize];
    fread(ucpBuffer, 1, nFileSize, filep);

    fclose(filep);

    ElfParser::tsELFHeaderInfo stTempResult;
    bool bRetVal = ParseHeader(ucpBuffer, nFileSize, &stTempResult);
    *stpResult = stTempResult;
    return bRetVal;

}




bool ElfParser::ParseHeader(unsigned char* ucpBuffer, int nBufferLength
	, ElfParser::tsELFHeaderInfo* stpResult)
{
	printf("\nHi I am the parser!");
	if(ucpBuffer[0] != 0x7F || ucpBuffer[1] != 'E' 
		|| ucpBuffer[2] != 'L' || ucpBuffer[3] != 'F')
	{
		printf("\nFile does not start with ELF identifier!");
		return false;
	}
	ElfParser::tsELFHeaderInfo stResult;
	if(ucpBuffer[4] == 0x01)
	{
		stResult.b32bit = true;
		stResult.b64bit = false;
	}
	else if(ucpBuffer[4] == 0x02)
	{
		stResult.b32bit = false;
		stResult.b64bit = true;
	}	
	else
	{
		stResult.bValid = false;
		return false;
	}

	if(ucpBuffer[5] == 0x01)
	{
		stResult.bLittleEndian = true;
		stResult.bBigEndian = false;
	}
	else if(ucpBuffer[5] == 0x02)
	{
		stResult.bLittleEndian = false;
		stResult.bBigEndian = true;
	}	
	else
	{
		stResult.bValid = false;
		return false;
	}

	stResult.bValid = true;

	stResult.ucELFVersion = ucpBuffer[6];

	stResult.ucOSABI = ucpBuffer[7];

	stResult.ucABIVersion = ucpBuffer[8];

	EndianReader::ReadMemoryIntoVariable(stResult.sType
		, ucpBuffer + 16, 2, stResult.bLittleEndian);

	EndianReader::ReadMemoryIntoVariable(stResult.sInstructionSetID
		, ucpBuffer + 18, 2, stResult.bLittleEndian);

	EndianReader::ReadMemoryIntoVariable(stResult.unELFVersion
		, ucpBuffer + 20, 4, stResult.bLittleEndian);	

	int nPointerSizeInByte = (stResult.b32bit ? 4 : 8);
	int nIndex = 24;

	EndianReader::ReadMemoryIntoVariable(stResult.ullProgramEntryPos	//read the memory
		, ucpBuffer + nIndex, nPointerSizeInByte, stResult.bLittleEndian);

	nIndex += nPointerSizeInByte;	//then move the pointer 

	EndianReader::ReadMemoryIntoVariable(stResult.ullProgramHeaderOffset
		, ucpBuffer + nIndex, nPointerSizeInByte, stResult.bLittleEndian);

	nIndex += nPointerSizeInByte;

	EndianReader::ReadMemoryIntoVariable(stResult.ullSectionHeaderOffset
		, ucpBuffer + nIndex, nPointerSizeInByte, stResult.bLittleEndian);

	nIndex += nPointerSizeInByte;

	EndianReader::ReadMemoryIntoVariable(stResult.unFlags
		, ucpBuffer + nIndex, 4, stResult.bLittleEndian);

	nIndex += 4;

	EndianReader::ReadMemoryIntoVariable(stResult.usELFHeaderSize
		, ucpBuffer + nIndex, 2, stResult.bLittleEndian);

	nIndex += 2;

	EndianReader::ReadMemoryIntoVariable(stResult.usProgramHeaderEntrySize
		, ucpBuffer + nIndex, 2, stResult.bLittleEndian);

	nIndex += 2;

	EndianReader::ReadMemoryIntoVariable(stResult.usProgramHeaderNumberOfEntries
		, ucpBuffer + nIndex, 2, stResult.bLittleEndian);

	nIndex += 2;

	EndianReader::ReadMemoryIntoVariable(stResult.usSectionHeaderEntrySize
		, ucpBuffer + nIndex, 2, stResult.bLittleEndian);

	nIndex += 2;

	EndianReader::ReadMemoryIntoVariable(stResult.usSectionHeaderNumberOfEntries
		, ucpBuffer + nIndex, 2, stResult.bLittleEndian);

	nIndex += 2;

	EndianReader::ReadMemoryIntoVariable(stResult.usStringTableSectionIndex
		, ucpBuffer + nIndex, 2, stResult.bLittleEndian);

	*stpResult = stResult;
	return true;
}



void ElfParser::PrintHeaderInfo(ElfParser::tsELFHeaderInfo stHeaderInfo)
{
	if(!stHeaderInfo.bValid)
	{
		printf("\nInvalid info");
		return;
	}

	if(stHeaderInfo.b32bit)
	{
		printf("\nAddressing: 32bit");
	}
	else
	{
		printf("\nAddressing: 64bit");
	}

	if(stHeaderInfo.bLittleEndian)
	{
		printf("\nEndian: Little Endian");
	}
	else
	{
		printf("\nEndian: Big Endian");
	}

	printf("\nELF Version: %d", stHeaderInfo.ucELFVersion);

	printf("\nOS/ABI Specific Extension: %d", stHeaderInfo.ucOSABI);

	printf("\nABI Version: %d", stHeaderInfo.ucABIVersion);

	printf("\nELF Type: %d", stHeaderInfo.sType);
	if(stHeaderInfo.sType == 0)
		printf(" (No Type)");
	else if(stHeaderInfo.sType == 1)
		printf(" (Relocatable File)");
	else if(stHeaderInfo.sType == 2)
		printf(" (Executable File)");
	else if(stHeaderInfo.sType == 3)
		printf(" (Shared Object File)");
	else if(stHeaderInfo.sType == 4)
		printf(" (Core File)");
	else if(stHeaderInfo.sType >= 0xFE00 && stHeaderInfo.sType <= 0xFEFF)
		printf(" (Operating System-specific)");
	else if(stHeaderInfo.sType >= 0xFF00 && stHeaderInfo.sType <= 0xFFFF)
		printf(" (Processor-specific)");
	else
		printf(" (Reserved/Unassigned)");


	printf("\nsInstructionSetID = %d", stHeaderInfo.sInstructionSetID);

	printf("\nunELFVersion = %d", stHeaderInfo.unELFVersion);

	printf("\nullProgramEntryPos = %lld", stHeaderInfo.ullProgramEntryPos);

	printf("\nullProgramHeaderOffset = %lld", stHeaderInfo.ullProgramHeaderOffset);

	printf("\nullSectionHeaderOffset = %lld", stHeaderInfo.ullSectionHeaderOffset);

	printf("\nunFlags = %d", stHeaderInfo.unFlags);

	printf("\nusELFHeaderSize = %d", stHeaderInfo.usELFHeaderSize);

	printf("\nusProgramHeaderEntrySize = %d", stHeaderInfo.usProgramHeaderEntrySize);

	printf("\nusProgramHeaderNumberOfEntries = %d", stHeaderInfo.usProgramHeaderNumberOfEntries);

	printf("\nusSectionHeaderEntrySize = %d", stHeaderInfo.usSectionHeaderEntrySize);

	printf("\nusSectionHeaderNumberOfEntries = %d", stHeaderInfo.usSectionHeaderNumberOfEntries);

	printf("\nusStringTableSectionIndex = %d", stHeaderInfo.usStringTableSectionIndex);

}

void ElfParser::ParseSection(unsigned char* ucpBuffer, unsigned int unSectionStartIndex, bool bIs32bit, bool bIsLittleEndian, tsSectionHeaderInfo* stpResult,
	unsigned int unStringTableStartIndex)
{
	int unAddressLength = bIs32bit ? 4 : 8;

	unsigned char* ucpIndex = ucpBuffer + unSectionStartIndex;

	EndianReader::ReadMemoryIntoVariable(stpResult->unSectionNameIndex, ucpIndex, 4, bIsLittleEndian);

	ucpIndex += 4;

	EndianReader::ReadMemoryIntoVariable(stpResult->unSectionType, ucpIndex, 4, bIsLittleEndian);

	ucpIndex += 4;

	EndianReader::ReadMemoryIntoVariable(stpResult->ullSectionFlags, ucpIndex, unAddressLength, bIsLittleEndian);

	ucpIndex += unAddressLength;

	EndianReader::ReadMemoryIntoVariable(stpResult->ullSectionAddress, ucpIndex, unAddressLength, bIsLittleEndian);

	ucpIndex += unAddressLength;

	EndianReader::ReadMemoryIntoVariable(stpResult->ullSectionOffset, ucpIndex, unAddressLength, bIsLittleEndian);

	ucpIndex += unAddressLength;

	EndianReader::ReadMemoryIntoVariable(stpResult->ullSectionSize, ucpIndex, unAddressLength, bIsLittleEndian);

	ucpIndex += unAddressLength;

	EndianReader::ReadMemoryIntoVariable(stpResult->unSectionHeaderIndex, ucpIndex, 4, bIsLittleEndian);

	ucpIndex += 4;

	EndianReader::ReadMemoryIntoVariable(stpResult->unSectionInfo, ucpIndex, 4, bIsLittleEndian);

	ucpIndex += 4;

	EndianReader::ReadMemoryIntoVariable(stpResult->ullSectionAddressAllignment, ucpIndex, unAddressLength, bIsLittleEndian);

	ucpIndex += unAddressLength;

	EndianReader::ReadMemoryIntoVariable(stpResult->ullSectionEntrySize, ucpIndex, unAddressLength, bIsLittleEndian);

	if(unStringTableStartIndex != -1)
	{
		char* cpName = (char*)(ucpBuffer) + unStringTableStartIndex + stpResult->unSectionNameIndex;
		unsigned int unNameLength = strlen(cpName);
		if(unNameLength == 0)
		{
			stpResult->cpSectionName = 0;
		} 
		else
		{
		stpResult->cpSectionName = new char[unNameLength + 1];
		strcpy(stpResult->cpSectionName, cpName);
		}
	}
	else
	{
		stpResult->cpSectionName = 0;
	}

}

void ElfParser::PrintSectionHeaderInfo(tsSectionHeaderInfo stStructHeader)
{
	printf("\n------SectionHeaderInfo:------");
	printf("\nunSectionID= %d", stStructHeader.unSectionID);
	printf("\nunSectionNameIndex= %d (%s)", stStructHeader.unSectionNameIndex, stStructHeader.cpSectionName);
	printf("\nunSectionType= %d", stStructHeader.unSectionType);
	switch(stStructHeader.unSectionType)
	{
		case 0:
			printf(" (Null)");
			break;
		case 1:
			printf(" (Progbits)");
			break;
		case 2:
			printf(" (Symtab)");
			break;
		case 3:
			printf(" (Strtab)");
			break;
		case 4:
			printf(" (Rela)");
			break;
		case 5:
			printf(" (Hash)");
			break;
		case 6:
			printf(" (Dynamic)");
			break;
		case 7:
			printf(" (Note)");
			break;
		case 8:
			printf(" (Nobits)");
			break;
		case 9:
			printf(" (Rel)");
			break;
		case 10:
			printf(" (Shlib)");
			break;
		case 11:
			printf(" (Dynsym)");
			break;
		case 14:
			printf(" (Init_Array)");
			break;
		case 15:
			printf(" (Fini_Array)");
			break;
		case 16:
			printf(" (Preinit_Array)");
			break;	
		case 17:
			printf(" (Group)");
			break;
		case 18:
			printf(" (Symtab_Shndx)");
			break;
		default:
			if(stStructHeader.unSectionType >= 0x60000000 && stStructHeader.unSectionType <= 0x6fffffff)
				printf(" (OS-Specific)");
			else if(stStructHeader.unSectionType >= 0x70000000 && stStructHeader.unSectionType <= 0x7fffffff)
				printf(" (Processor-Specific)");
			else
				printf(" (User-Specific)");
	}


	printf("\nullSectionFlags= %lld", stStructHeader.ullSectionFlags);
	printf("\nullSectionAddress= %lld", stStructHeader.ullSectionAddress);
	printf("\nullSectionOffset= %lld", stStructHeader.ullSectionOffset);
	printf("\nullSectionSize= %lld", stStructHeader.ullSectionSize);
	printf("\nunSectionHeaderIndex= %d", stStructHeader.unSectionHeaderIndex);
	printf("\nunSectionInfo= %d", stStructHeader.unSectionInfo);
	printf("\nullSectionAddressAllignment= %lld", stStructHeader.ullSectionAddressAllignment);
	printf("\nullSectionEntrySize= %lld", stStructHeader.ullSectionEntrySize);
}

void ElfParser::ParseSymbolInfo(unsigned char* ucpBuffer, unsigned int unSymbolStartIndex, bool bIs32bit, bool bIsLittleEndian, tsSymbolInfo* stResults, unsigned int unStringTableIndex)
{
	//TODO
	unsigned char* ucpIndex = ucpBuffer + unSymbolStartIndex; 

	EndianReader::ReadMemoryIntoVariable(stResults->unSymbolNameIndex, ucpIndex, 4, bIsLittleEndian);
	ucpIndex += 4;

	if(bIs32bit)	//order of fields is different for 32 and 64 bits
	{
		EndianReader::ReadMemoryIntoVariable(stResults->ullSymbolValue, ucpIndex, 4, bIsLittleEndian);
		ucpIndex += 4;

		EndianReader::ReadMemoryIntoVariable(stResults->ullSymbolSize, ucpIndex, 4, bIsLittleEndian);
		ucpIndex += 4;

		stResults->ucSymbolInfo = *ucpIndex;
		ucpIndex++;

		stResults->ucSymbolOther = *ucpIndex;
		ucpIndex++;

		EndianReader::ReadMemoryIntoVariable(stResults->usBoundSectionHeaderIndex, ucpIndex, 2, bIsLittleEndian);
	}
	else
	{
		stResults->ucSymbolInfo = *ucpIndex;
		ucpIndex++;

		stResults->ucSymbolOther = *ucpIndex;
		ucpIndex++;

		EndianReader::ReadMemoryIntoVariable(stResults->usBoundSectionHeaderIndex, ucpIndex, 2, bIsLittleEndian);
		ucpIndex += 2;

		EndianReader::ReadMemoryIntoVariable(stResults->ullSymbolValue, ucpIndex, 8, bIsLittleEndian);
		ucpIndex += 8;

		EndianReader::ReadMemoryIntoVariable(stResults->ullSymbolSize, ucpIndex, 8, bIsLittleEndian);	
	}

	if(unStringTableIndex != -1 && stResults->unSymbolNameIndex != 0)
	{
		char* cpName = (char*)(ucpBuffer) + unStringTableIndex + stResults->unSymbolNameIndex;
		unsigned int unNameLength = strlen(cpName);
		if(unNameLength == 0)
		{
			stResults->cpSymbolName = 0;
		} 
		else
		{
		stResults->cpSymbolName = new char[unNameLength + 1];
		strcpy(stResults->cpSymbolName, cpName);
		}
	}
	else
	{
		stResults->cpSymbolName = 0;
	}
}

void ElfParser::PrintSymbolInfo(tsSymbolInfo stSymbolInfo)
{
	printf("\n-----SymbolInfo:-----");
	printf("\nunSymbolID= %d", stSymbolInfo.unSymbolID);
	printf("\nunSymbolNameIndex= %d", stSymbolInfo.unSymbolNameIndex);
	printf(" (%s)", stSymbolInfo.cpSymbolName);
	printf("\nullSymbolValue= %lld", stSymbolInfo.ullSymbolValue);
	printf("\nullSymbolSize= %lld", stSymbolInfo.ullSymbolSize);
	printf("\nucSymbolInfo= %d", stSymbolInfo.ucSymbolInfo);
	printf("\nucSymbolOther= %d", stSymbolInfo.ucSymbolOther);
	printf("\nusBoundSectionHeaderIndex= %d", stSymbolInfo.usBoundSectionHeaderIndex);
}
//Non-static versions
ElfParser::ElfParser(char* cpFileName)
{
	FILE* filep = fopen(cpFileName, "rb");
	if(filep == NULL)
	{
		printf("\nCan not open %s!", cpFileName);
		return;
	}
	fseek (filep, 0, SEEK_END);
    unFileSize = ftell (filep);
    rewind(filep);

    ucpFileBuffer = new unsigned char[unFileSize];
    fread(ucpFileBuffer, 1, unFileSize, filep);

    fclose(filep);

	stpSectionHeaderInfo = NULL;
	stpSymbolInfo = NULL;

}

ElfParser::ElfParser(unsigned char* ucpBuffer, unsigned int unBufferSize)
{
	ucpFileBuffer = ucpBuffer;
	unFileSize = unBufferSize;

	stpSectionHeaderInfo = NULL;
	stpSymbolInfo = NULL;
}

ElfParser::~ElfParser()
{
	printf("\nCleaning up");

	for(int nIndex = 0; nIndex < unSymbolCount; nIndex++)
	{
		if(stpSymbolInfo[nIndex].cpSymbolName != NULL)
			delete []stpSymbolInfo[nIndex].cpSymbolName;
	}

	delete []stpSymbolInfo;

	for(int nIndex = 0; nIndex < stELFHeaderInfo.usSectionHeaderNumberOfEntries; nIndex++)
	{
		if(stpSectionHeaderInfo[nIndex].cpSectionName !=NULL)
			delete []stpSectionHeaderInfo[nIndex].cpSectionName;
	}

	delete []stpSectionHeaderInfo;
}

bool ElfParser::ParseHeader()
{
	ParseHeader(ucpFileBuffer, unFileSize, &stELFHeaderInfo);
}

void ElfParser::PrintHeaderInfo()
{
	PrintHeaderInfo(stELFHeaderInfo);
}

void ElfParser::ParseAllSections()
{
	tsSectionHeaderInfo stStringTableHeader;
	unsigned long long ullSectionStartIndex = stELFHeaderInfo.ullSectionHeaderOffset + stELFHeaderInfo.usStringTableSectionIndex * stELFHeaderInfo.usSectionHeaderEntrySize; 
	ParseSection(ucpFileBuffer, ullSectionStartIndex, stELFHeaderInfo.b32bit, stELFHeaderInfo.bLittleEndian, &stStringTableHeader);
	unsigned int unStringTableStartIndex = stStringTableHeader.ullSectionOffset;


	stpSectionHeaderInfo = new tsSectionHeaderInfo[stELFHeaderInfo.usSectionHeaderNumberOfEntries];	//create section info containers

	for(int nIndex = 0; nIndex < stELFHeaderInfo.usSectionHeaderNumberOfEntries; nIndex++)
	{
		unsigned long long ullSectionStartIndex = stELFHeaderInfo.ullSectionHeaderOffset + nIndex * stELFHeaderInfo.usSectionHeaderEntrySize; 
		ParseSection(ucpFileBuffer, ullSectionStartIndex, stELFHeaderInfo.b32bit, stELFHeaderInfo.bLittleEndian, stpSectionHeaderInfo + nIndex, unStringTableStartIndex);
		stpSectionHeaderInfo[nIndex].unSectionID = nIndex;

		if(stpSectionHeaderInfo[nIndex].unSectionType == 2)
		{
			unSymbolSectionID = nIndex;
			unSymbolCount = stpSectionHeaderInfo[nIndex].ullSectionSize / stpSectionHeaderInfo[nIndex].ullSectionEntrySize;
		}
		if(!stpSectionHeaderInfo[nIndex].cpSectionName){continue;}	//if no name is available skip the check
		if(strstr(stpSectionHeaderInfo[nIndex].cpSectionName, ".strtab") == stpSectionHeaderInfo[nIndex].cpSectionName)
		{
			unStrtabSectionID = nIndex;
		}
	}
}

void ElfParser::PrintAllSectionHeaderInfo()
{
	for(int nIndex = 0; nIndex < stELFHeaderInfo.usSectionHeaderNumberOfEntries; nIndex++)
	{
		PrintSectionHeaderInfo(*(stpSectionHeaderInfo + nIndex));	
	}
}

void ElfParser::ParseAllSymbols()
{
	stpSymbolInfo = new tsSymbolInfo[unSymbolCount];	//create symbol storage

	for(int nIndex = 0; nIndex < unSymbolCount; nIndex++)
	{
		unsigned long long ullSymbolStartIndex = stpSectionHeaderInfo[unSymbolSectionID].ullSectionOffset + nIndex * stpSectionHeaderInfo[unSymbolSectionID].ullSectionEntrySize;
		ParseSymbolInfo(ucpFileBuffer, ullSymbolStartIndex, stELFHeaderInfo.b32bit, stELFHeaderInfo.bLittleEndian, stpSymbolInfo + nIndex,
			stpSectionHeaderInfo[unStrtabSectionID].ullSectionOffset);

		stpSymbolInfo[nIndex].unSymbolID = nIndex;
	}
}

void ElfParser::PrintAllSymbolInfo()
{
	for(int nIndex = 0; nIndex < unSymbolCount; nIndex++)
	{
		PrintSymbolInfo(stpSymbolInfo[nIndex]);
	}
}