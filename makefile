all:
	g++ -o Test Tester.cpp ElfParser.cpp
	./Test

clean:
	rm Test 