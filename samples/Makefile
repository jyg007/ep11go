.PHONY: all clean

BIN_DIR := bin
SAMPLES := $(basename $(notdir $(wildcard *.go)))

all:
	@mkdir -p $(BIN_DIR)
	@for sample in $(SAMPLES); do \
		echo "Building $$sample"; \
		go build -o $(BIN_DIR)/$$sample ./$$sample.go; \
	done

clean:
	rm -rf $(BIN_DIR)
