all: main

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@

lib%.so: %.o
	$(CXX) -shared $(CXXFLAGS) $< -o $@

main: main.o libmy.so
	$(CXX) $(CXXFLAGS) main.o -L. -lmy -o main

clean:
	rm -f *.o *.so

.PHONY: clean main
