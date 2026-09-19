package main

import (
	"os"
	"path/filepath"
)

// Sockets are shared by all builds so only one identity can serve this account.
// Persistent files and Keychain groups remain specific to the compiled identity.
func pasuRuntimeDirectory(home string) string {
	return filepath.Join(home, ".ssh", "pasu")
}

func pasuDataDirectory(home string) string {
	return filepath.Join(pasuRuntimeDirectory(home), "profiles", pasuTeamID+"."+pasuGUIIdentifier)
}

func preparePasuDirectories(home string) error {
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	for _, path := range []string{pasuRuntimeDirectory(home), filepath.Join(pasuRuntimeDirectory(home), "profiles"), pasuDataDirectory(home)} {
		if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
		if err := requireOwnedDir(path); err != nil {
			return err
		}
	}
	return nil
}
