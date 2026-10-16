package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/rakeshnitb23/opfence/internal/catalog"
)

// Apply moves the findings that are not skipped into the vault and writes
// placeholders into the files. A value already in the vault keeps its
// placeholder. Every secret is stored, and read back, before any file is
// touched, so a failure can never leave a file holding a placeholder whose
// value is lost. It returns the files it changed.
func Apply(findings []Finding, c *catalog.Catalog, v *Vault) ([]string, error) {
	existing, err := v.List()
	if err != nil {
		return nil, err
	}
	type key struct{ provider, value string }
	byValue := map[key]*Secret{}
	names := map[string]bool{}
	for _, s := range existing {
		byValue[key{s.Provider, s.Value}] = s
		names[s.Account()] = true
	}
	touched := map[*Secret]bool{}
	perFile := map[string][]*Secret{}
	for _, f := range findings {
		if f.Skip != "" {
			continue
		}
		s := byValue[key{f.Provider, f.Value}]
		if s == nil {
			var prefixes []string
			if p := c.Provider(f.Provider); p != nil {
				prefixes = p.Detect.Prefixes
			}
			ph, err := NewPlaceholder(f.Value, prefixes)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", f.File, f.Where, err)
			}
			s = &Secret{Provider: f.Provider, Name: f.Name, Value: f.Value, Placeholder: ph}
			for i := 2; names[s.Account()]; i++ {
				s.Name = f.Name + "_" + strconv.Itoa(i)
			}
			names[s.Account()] = true
			byValue[key{f.Provider, f.Value}] = s
		}
		if !slices.Contains(s.Sources, f.File) {
			s.Sources = append(s.Sources, f.File)
		}
		touched[s] = true
		perFile[f.File] = append(perFile[f.File], s)
	}
	for s := range touched {
		if err := v.Put(s); err != nil {
			return nil, err
		}
		raw, err := v.Store.Get(s.Account())
		if err != nil || !bytes.Contains([]byte(raw), []byte(s.Placeholder)) {
			return nil, fmt.Errorf("the keychain did not keep %s/%s; no files were changed", s.Provider, s.Name)
		}
	}
	var changed []string
	files := make([]string, 0, len(perFile))
	for f := range perFile {
		files = append(files, f)
	}
	slices.Sort(files)
	for _, f := range files {
		ok, err := replaceInFile(f, func(data []byte) []byte {
			for _, s := range perFile[f] {
				data = bytes.ReplaceAll(data, []byte(s.Value), []byte(s.Placeholder))
			}
			return data
		})
		if err != nil {
			return changed, err
		}
		if ok {
			changed = append(changed, f)
		}
	}
	return changed, nil
}

// Undo writes real values back over their placeholders in every file the
// secrets came from, and returns the files it changed.
func Undo(secrets []*Secret) ([]string, error) {
	perFile := map[string][]*Secret{}
	for _, s := range secrets {
		for _, f := range s.Sources {
			perFile[f] = append(perFile[f], s)
		}
	}
	var changed []string
	files := make([]string, 0, len(perFile))
	for f := range perFile {
		files = append(files, f)
	}
	slices.Sort(files)
	for _, f := range files {
		ok, err := replaceInFile(f, func(data []byte) []byte {
			for _, s := range perFile[f] {
				data = bytes.ReplaceAll(data, []byte(s.Placeholder), []byte(s.Value))
			}
			return data
		})
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return changed, err
		}
		if ok {
			changed = append(changed, f)
		}
	}
	return changed, nil
}

// replaceInFile rewrites path through fn, atomically and keeping its mode.
func replaceInFile(path string, fn func([]byte) []byte) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	out := fn(bytes.Clone(data))
	if bytes.Equal(out, data) {
		return false, nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".opfence-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), path)
}
