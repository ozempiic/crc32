CC = gcc
CFLAGS = -Wall -I.
LDFLAGS = -lpsapi

BUILD_DIR = build
SRC_DIR = .

SRCS = section_monitor.c main.c test_tampering.c
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)
DEPS = $(OBJS:.o=.d)

TARGETS = $(BUILD_DIR)/section_monitor.exe $(BUILD_DIR)/test_tampering.exe

all: $(BUILD_DIR) $(TARGETS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/section_monitor.exe: $(BUILD_DIR)/section_monitor.o $(BUILD_DIR)/main.o
	$(CC) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/test_tampering.exe: $(BUILD_DIR)/test_tampering.o
	$(CC) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean