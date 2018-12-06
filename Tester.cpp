#include <stdio.h>
#include "ElfParser.h"

int main(int argc, char *argv[])
{
	//ElfParser::tsELFHeaderInfo stResult;

	//ElfParser::Parse("Test.o", &stResult);

	//ElfParser::PrintHeaderInfo(stResult);

	if(argc < 2)
	{
		printf("Wrong usage. Example: $./Tester ElfFileToParse.o\n");
		return -1;
	}
	ElfParser TestInstance("Test.o");

	TestInstance.ParseHeader();
	TestInstance.PrintHeaderInfo();
	TestInstance.ParseAllSections();
	TestInstance.PrintAllSectionHeaderInfo();

	printf("\nSymbol Section is: %d", TestInstance.unSymbolSectionID);
	printf("\nSymbol Count: %d", TestInstance.unSymbolCount);
	printf("\nString Section is: %d", TestInstance.unStrtabSectionID);

	TestInstance.ParseAllSymbols();
	TestInstance.PrintAllSymbolInfo();

	printf("\n");
	return 0;
}