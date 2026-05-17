INSTALL_DIR := $(HOME)/.local/bin
TARGET      := qute-1pass-sidecar
SRC         := qute-1pass-sidecar.c

$(TARGET): $(SRC)
	gcc -O2 -o $@ $< -lpthread

install: $(TARGET)
	install -Dm755 $(TARGET) $(INSTALL_DIR)/$(TARGET)
	@echo "Installed to $(INSTALL_DIR)/$(TARGET)"
	@echo ""
	@echo "To register as a trusted browser, run once as root:"
	@echo "  echo '$(TARGET)' | sudo tee -a /etc/1password/custom_allowed_browsers"

clean:
	rm -f $(TARGET)

.PHONY: install clean
