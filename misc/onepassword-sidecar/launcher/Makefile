USER_INSTALL_DIR   := $(HOME)/.local/bin
SYSTEM_INSTALL_DIR := /usr/local/bin
TARGET             := qute-1pass-sidecar
SRC                := qute-1pass-sidecar.c

$(TARGET): $(SRC)
	gcc -O2 -o $@ $< -lpthread

# install — user-local (~/.local/bin), useful for development/testing.
# Does NOT satisfy 1Password's root-owned binary requirement; use
# install-system for the native backend to work.
install: $(TARGET)
	install -Dm755 $(TARGET) $(USER_INSTALL_DIR)/$(TARGET)
	@echo "Installed to $(USER_INSTALL_DIR)/$(TARGET) (user-local)"
	@echo ""
	@echo "NOTE: 1Password-BrowserSupport requires the launcher to be"
	@echo "root-owned and listed in /etc/1password/custom_allowed_browsers."
	@echo "Run 'make install-system' for the native backend."

# install-system — installs root-owned to /usr/local/bin (requires sudo).
# Required for --backend native; BrowserSupport checks /proc/<ppid>/exe
# ownership and the custom_allowed_browsers whitelist.
install-system: $(TARGET)
	sudo install -Dm755 -o root -g root $(TARGET) $(SYSTEM_INSTALL_DIR)/$(TARGET)
	@echo "Installed to $(SYSTEM_INSTALL_DIR)/$(TARGET) (root-owned)"
	@echo ""
	@echo "If not already done, register as a trusted browser:"
	@echo "  echo '$(TARGET)' | sudo tee -a /etc/1password/custom_allowed_browsers"

clean:
	rm -f $(TARGET)

.PHONY: install install-system clean
