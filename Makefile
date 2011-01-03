# (c) 2010-2011 by Anton Korenyushkin

CXXFLAGS=-pedantic -Wall -Wextra -Werror
LDFLAGS=-lboost_program_options-mt

all: ecilop

ecilop: ecilop.cc
	$(CXX) $< -o $@ $(CXXFLAGS) -Wl,-Bstatic $(LDFLAGS) -lstdc++ -Wl,-Bdynamic

ecilop-d: ecilop.cc
	$(CXX) $< -o $@ $(CXXFLAGS) $(LDFLAGS) -ggdb3

ecilop-c: ecilop.cc
	$(CXX) $< -o $@ $(CXXFLAGS) $(LDFLAGS) -fprofile-arcs -ftest-coverage

test: ecilop
	./test.py

test-d: ecilop-d
	./test.py ecilop-d

cov: ecilop-c
	rm -rf cov ecilop.gcda
	mkdir cov
	./test.py ecilop-c
	lcov -c -d . -o cov/cov.info
	genhtml -o cov cov/cov.info

clean:
	rm -rf ecilop ecilop-d ecilop-c ecilop.gcda ecilop.gcno cov

.PHONY: all test test-d cov clean
