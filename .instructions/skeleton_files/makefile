# ============================================================
# Makefile for CS311 Security Simulator
# ============================================================

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I./include
TARGET = simulator
SRCDIR = src
OBJDIR = obj

# Automatically find all .cpp files
SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SOURCES))

# Default target
all: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CXX) $(OBJECTS) -o $(TARGET)
	@echo "Build complete: ./$(TARGET)"

# Compile .cpp files to .o files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(OBJDIR)
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning build files..."
	rm -rf $(OBJDIR) $(TARGET)
	@echo "Clean complete"

# Run the simulator
run: $(TARGET)
	@echo "Running simulator..."
	./$(TARGET)

# Create necessary directories
setup:
	@echo "Creating project directories..."
	mkdir -p src include obj output archive
	@echo "Setup complete"

# Help target
help:
	@echo "CS311 Simulator Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make         - Build the simulator"
	@echo "  make run     - Build and run the simulator"
	@echo "  make clean   - Remove build artifacts"
	@echo "  make setup   - Create project directories"
	@echo "  make help    - Show this help message"

.PHONY: all clean run setup help