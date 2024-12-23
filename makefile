TESTS := $(sort $(wildcard test*.cxx))
SOURCES := $(filter-out $(TESTS),$(wildcard *.cxx))
HEADERS := $(wildcard *.h)
TARGETS := $(TESTS:.cxx=.exe)
RESULTS := $(TESTS:.cxx=.out)
CXXFLAGS := -std=c++11 -O3

.PHONY: all test clean
all: $(TARGETS)

$(TARGETS): %.exe: %.cxx $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $< $(SOURCES) -o $@

clean:
	rm -f $(TARGETS) $(RESULTS)

