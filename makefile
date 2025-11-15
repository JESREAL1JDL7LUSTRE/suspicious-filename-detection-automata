CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser
TARGET = simulator
SHELL := bash
SRCDIR = src
OBJDIR = obj

# Explicit list of source files (discovered in the workspace)
SOURCES = \
	$(SRCDIR)/main.cpp \
	$(SRCDIR)/regexparser/RegexParser.cpp \
	$(SRCDIR)/pda/PDAModule.cpp \
	$(SRCDIR)/dfa/DFAModule.cpp \
	$(SRCDIR)/jsonparser/JSONParser.cpp
# Map each source file `src/.../file.cpp` to `obj/.../file.o`
OBJECTS = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SOURCES))

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
