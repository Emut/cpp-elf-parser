#ifndef ELFPARSER_H
#define ELFPARSER_H 

class ElfParser
{
private:
	
public:
	struct tsELFHeaderInfo
	{
		bool bValid;
		bool b32bit;
		bool b64bit;
		bool bLittleEndian;
		bool bBigEndian;
		unsigned char ucELFVersion;
		unsigned char ucOSABI;
		unsigned char ucABIVersion;
		unsigned short sType;
		unsigned short sInstructionSetID;
		unsigned int unELFVersion;
		unsigned long long ullProgramEntryPos;
		unsigned long long ullProgramHeaderOffset;
		unsigned long long ullSectionHeaderOffset;
		unsigned int unFlags;
		unsigned short usELFHeaderSize;
		unsigned short usProgramHeaderEntrySize;
		unsigned short usProgramHeaderNumberOfEntries;
		unsigned short usSectionHeaderEntrySize;
		unsigned short usSectionHeaderNumberOfEntries;
		unsigned short usStringTableSectionIndex;

	};

	struct tsSectionHeaderInfo
	{
		unsigned int unSectionNameIndex; 
		unsigned int unSectionType;
		unsigned long long ullSectionFlags;
		unsigned long long ullSectionAddress;
		unsigned long long ullSectionOffset;
		unsigned long long ullSectionSize;
		unsigned int unSectionHeaderIndex;
		unsigned int unSectionInfo;
		unsigned long long ullSectionAddressAllignment;
		unsigned long long ullSectionEntrySize;
		char* cpSectionName;
		
	};

	struct tsSymbolInfo
	{
		unsigned int unSymbolNameIndex;
	};

	ElfParser(char* cpFileName);
	ElfParser(unsigned char* ucpBuffer, unsigned int unBufferLength);
	static bool ParseHeader(char* cpFileName, tsELFHeaderInfo* stpHeaderInfo);
	static bool ParseHeader(unsigned char* ucpBuffer, int nBufferLength, tsELFHeaderInfo* stpHeaderInfo);
	static void PrintHeaderInfo(tsELFHeaderInfo stHeaderInfo);
	static void ParseSection(unsigned char* ucpBuffer, unsigned int unSectionStartIndex, bool bIs32bit, bool bIsLittleEndian, tsSectionHeaderInfo* stResults, 
		unsigned int unStringTableIndex = -1);
	static void PrintSectionHeaderInfo(tsSectionHeaderInfo stStructHeader);
	bool ParseHeader();
	void PrintHeaderInfo();
	void ParseAllSections();
	void PrintAllSectionHeaderInfo();
	

private:
	unsigned char* ucpFileBuffer;
	unsigned int unFileSize;
	tsELFHeaderInfo stELFHeaderInfo;
	tsSectionHeaderInfo* stpSectionHeaderInfo;

};




#endif