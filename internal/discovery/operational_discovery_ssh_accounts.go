package discovery

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nagi1/larainspect/internal/model"
)

func (service SnapshotService) discoverSSHAccounts() ([]model.SSHAccount, []model.Unknown) {
	accounts := []model.SSHAccount{}
	unknowns := []model.Unknown{}
	seenPaths := map[string]struct{}{}

	for _, pattern := range service.sshAccountPatterns {
		matches, err := service.expandConfigPattern(pattern)
		if err != nil {
			unknowns = append(unknowns, newPathUnknown(operationalDiscoveryCheckID, "Unable to inspect SSH account path", pattern, err))
			continue
		}

		for _, matchedPath := range matches {
			cleanPath := filepath.Clean(matchedPath)
			if _, seen := seenPaths[cleanPath]; seen {
				continue
			}
			seenPaths[cleanPath] = struct{}{}

			account, accountUnknowns := service.inspectSSHAccount(cleanPath)
			unknowns = append(unknowns, accountUnknowns...)
			if strings.TrimSpace(account.User) == "" {
				continue
			}

			accounts = append(accounts, account)
		}
	}

	model.SortSSHAccounts(accounts)
	return accounts, compactUnknowns(unknowns)
}

func (service SnapshotService) inspectSSHAccount(sshDirPath string) (model.SSHAccount, []model.Unknown) {
	homePath := filepath.Clean(filepath.Dir(sshDirPath))
	account := model.SSHAccount{
		User:     sshAccountUser(homePath),
		HomePath: homePath,
	}
	if account.User == "" {
		return model.SSHAccount{}, nil
	}

	unknowns := []model.Unknown{}
	sshDirRecord, sshDirUnknown := service.inspectAbsolutePathRecord(".ssh", sshDirPath)
	if sshDirUnknown != nil {
		unknowns = append(unknowns, *sshDirUnknown)
	}
	account.SSHDir = sshDirRecord

	authorizedKeysPath := filepath.Join(sshDirPath, "authorized_keys")
	authorizedKeysRecord, authorizedKeysUnknown := service.inspectAbsolutePathRecord(".ssh/authorized_keys", authorizedKeysPath)
	if authorizedKeysUnknown != nil {
		unknowns = append(unknowns, *authorizedKeysUnknown)
	}
	account.AuthorizedKeys = authorizedKeysRecord

	privateKeys, privateKeyUnknowns := service.collectSSHPrivateKeys(sshDirPath)
	account.PrivateKeys = privateKeys
	unknowns = append(unknowns, privateKeyUnknowns...)

	return account, unknowns
}

func (service SnapshotService) collectSSHPrivateKeys(sshDirPath string) ([]model.PathRecord, []model.Unknown) {
	privateKeys := []model.PathRecord{}
	unknowns := []model.Unknown{}

	walkErr := service.walkDirectory(sshDirPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			unknowns = append(unknowns, newPathUnknown(operationalDiscoveryCheckID, "Unable to inspect SSH account key path", path, err))
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if path == sshDirPath {
			return nil
		}
		if entry.IsDir() {
			return filepath.SkipDir
		}

		if !looksLikeSSHPrivateKey(path) {
			return nil
		}

		record, recordUnknown := service.inspectAbsolutePathRecord(filepath.ToSlash(filepath.Join(".ssh", filepath.Base(path))), path)
		if recordUnknown != nil {
			unknowns = append(unknowns, *recordUnknown)
			return nil
		}

		privateKeys = append(privateKeys, record)
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, context.Canceled) {
		unknowns = append(unknowns, newPathUnknown(operationalDiscoveryCheckID, "SSH account key walk failed", sshDirPath, walkErr))
	}

	model.SortPathRecords(privateKeys)
	return privateKeys, unknowns
}

func sshAccountUser(homePath string) string {
	cleanHomePath := filepath.Clean(homePath)
	switch cleanHomePath {
	case ".", "/":
		return ""
	case "/root":
		return "root"
	default:
		return filepath.Base(cleanHomePath)
	}
}

func looksLikeSSHPrivateKey(path string) bool {
	baseName := strings.ToLower(filepath.Base(path))
	if strings.HasSuffix(baseName, ".pub") {
		return false
	}

	for _, ignoredName := range []string{"authorized_keys", "config", "known_hosts"} {
		if baseName == ignoredName {
			return false
		}
	}

	commonPrivateKeyNames := []string{
		"id_rsa",
		"id_dsa",
		"id_ecdsa",
		"id_ed25519",
		"identity",
	}
	if slices.Contains(commonPrivateKeyNames, baseName) {
		return true
	}

	return strings.HasSuffix(baseName, ".pem") || strings.HasSuffix(baseName, ".key")
}
