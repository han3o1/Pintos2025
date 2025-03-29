CC = gcc
CFLAGS = -g -Wall

# Directories
BUILD_DIR = build
SRC_DIR = src
TEST_DIR = tests
THREADS_DIR = threads

# Target binary
TARGET = pintos

# Sources and object files
SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Default target
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET)

# Run tests
run: $(TARGET)
	$(TARGET) -- -q run alarm-single

# Run alarm clock test
tests/threads/tests: $(TARGET)
	$(TARGET) -- -q run alarm-single
	$(TARGET) -- -q run alarm-negative
	$(TARGET) -- -q run alarm-priority
	$(TARGET) -- -q run alarm-simultaneous

# Compile object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build files
clean:
	rm -f $(BUILD_DIR)/*.o $(TARGET)

.PHONY: clean

