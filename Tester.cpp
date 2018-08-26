#include <stdio.h>
#include "ElfParser.h"

int main()
{
	//ElfParser::tsELFHeaderInfo stResult;

	//ElfParser::Parse("Test.o", &stResult);

	//ElfParser::PrintHeaderInfo(stResult);

	ElfParser TestInstance("Test.o");

	TestInstance.ParseHeader();
	TestInstance.PrintHeaderInfo();
	TestInstance.ParseAllSections();
	TestInstance.PrintAllSectionHeaderInfo();

	printf("\n");
	return 0;
}