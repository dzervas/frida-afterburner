all: main

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@

lib%.so: %.o
	$(CXX) -shared $(CXXFLAGS) $< -o $@

main: main.o
	$(CXX) $(CXXFLAGS) main.o -o main

clean:
	rm -f *.o *.so

.PHONY: clean main
