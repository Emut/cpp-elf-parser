all:
	g++ -o Test Tester.cpp ElfParser.cpp

clean:
	rm Test 
