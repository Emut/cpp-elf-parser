#ifndef ENDIANREADER_HPP
#define ENDIANREADER_HPP

#include <stdio.h>

class EndianReader
{
public:
	template <typename T>
	static bool ReadMemoryIntoVariable(T& tVariable, void* vpMemoryStartAddress
		, int nMemorySize, bool bIsLittleEndian)
	{
		//printf("\nsize of t: %ld", sizeof(tVariable));
		if(sizeof(tVariable) < nMemorySize)
		{
			printf("\nEndianReader:Size of variable is smaller than memory size");
			return false;
		}
		tVariable = 0;	//reset it

		unsigned char* ucpByteToRead = (unsigned char*) vpMemoryStartAddress;
		if(!bIsLittleEndian)	//if big endian start reading from end (LSB)
			ucpByteToRead += nMemorySize - 1; 


		for(int nIndex = 0; nIndex < nMemorySize; nIndex++)
		{
			tVariable += (*ucpByteToRead)<<(8*nIndex);
			if(bIsLittleEndian)	//for either endian move to more significant digit
				ucpByteToRead++;
			else
				ucpByteToRead--;
		}

		return true;

	}
	
};



#endif
