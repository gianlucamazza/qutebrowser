INSTALL_DIR := $(HOME)/.local/share/qute-1pass
TARGET      := qute_browser_spoof.so
SRC         := qute_browser_spoof.c

$(TARGET): $(SRC)
	gcc -O2 -shared -fPIC -o $@ $< -ldl -lpthread

install: $(TARGET)
	install -Dm755 $(TARGET) $(INSTALL_DIR)/$(TARGET)
	@echo "Shim installed to $(INSTALL_DIR)/$(TARGET)"

clean:
	rm -f $(TARGET)

.PHONY: install clean
