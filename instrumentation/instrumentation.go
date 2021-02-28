// Copyright (c) 2016 - 2020 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package main

import (
	"fmt"
	"github.com/dave/dst"
	"github.com/dave/dst/decorator"
	"go/parser"
	"go/token"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

type Instrumenter interface {
	IsIgnored() bool
	AddFile(src string) error
	Instrument() ([]*dst.File, error)
	WriteInstrumentedFiles(packageBuildDir string, instrumented []*dst.File) (srcdst map[string]string, err error)
	WriteExtraFiles() ([]string, error)
}

type packageInstrumentationHelper struct {
	parsedFiles       map[string]*dst.File
	parsedFileSources map[*dst.File]string
	fset              *token.FileSet
	pkgPath           string
}

func makePackageInstrumentationHelper(pkgPath string) packageInstrumentationHelper {
	// Remove the package path vendor prefix so that everything, from this tool to
	// the agent instrumentation package works properly with the package path names
	// as if it wasn't vendored. By doing so, things like checking if the package
	// should be ignored, or looking up a hook descriptor is simplified and can
	// completely ignore the vendoring.
	pkgPath = unvendorPackagePath(pkgPath)

	return packageInstrumentationHelper{
		pkgPath: pkgPath,
	}
}

// AddFile parses the given Go source file `src` and adds it to the set of
// files to instrument if it is not ignored by a directive.
func (h *packageInstrumentationHelper) AddFile(src string) error {
	log.Printf("parsing file `%s`", src)
	if h.fset != nil {
		// The token fileset is required to later create the package node.
		h.fset = token.NewFileSet()
	}
	file, err := decorator.ParseFile(h.fset, src, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	if h.parsedFiles == nil {
		h.parsedFiles = make(map[string]*dst.File)
		h.parsedFileSources = make(map[*dst.File]string)
	}
	h.parsedFiles[src] = file
	h.parsedFileSources[file] = src
	return nil
}

func (h *packageInstrumentationHelper) instrument(v instrumentationVisitorFace) (instrumented []*dst.File, err error) {
	if len(h.parsedFiles) == 0 {
		log.Println("nothing to instrument")
		return nil, nil
	}

	root, err := dst.NewPackage(h.fset, h.parsedFiles, nil, nil)
	if err != nil {
		return nil, err
	}

	return v.instrument(root), nil
}

func (h *packageInstrumentationHelper) WriteInstrumentedFiles(buildDirPath string, instrumentedFiles []*dst.File) (srcdst map[string]string, err error) {
	srcdst = make(map[string]string, len(instrumentedFiles))
	for _, node := range instrumentedFiles {
		src := h.parsedFileSources[node]
		filename := filepath.Base(src)
		dest := filepath.Join(buildDirPath, filename)
		output, err := os.Create(dest)
		if err != nil {
			return nil, err
		}
		defer output.Close()
		// Add a go line directive in order to map it to its original source file.
		// Note that otherwise it uses the build directory but it is trimmed by the
		// compiler - so you end up with filenames without any leading path (eg.
		// myfile.go) leading to broken debuggers or stack traces.
		output.WriteString(fmt.Sprintf("//line %s:1\n", src))
		if err := writeFile(node, output); err != nil {
			return nil, err
		}
		srcdst[src] = dest
	}
	return srcdst, nil
}

type defaultPackageInstrumentation struct {
	packageInstrumentationHelper
	instrumentedFiles   map[*dst.File][]*hookpoint
	fullInstrumentation bool
	hookListFilepath    string
	packageBuildDir     string
}

func newDefaultPackageInstrumentation(pkgPath string, fullInstrumentation bool, packageBuildDir string) *defaultPackageInstrumentation {
	projectBuildDir := filepath.Join(packageBuildDir, "..")
	hookListFilepath := getHookListFilepath(projectBuildDir)

	return &defaultPackageInstrumentation{
		packageInstrumentationHelper: makePackageInstrumentationHelper(pkgPath),
		fullInstrumentation:          fullInstrumentation,
		hookListFilepath:             hookListFilepath,
		packageBuildDir:              packageBuildDir,
	}
}

func (h *defaultPackageInstrumentation) IsIgnored() bool {
	// Check if the instrumentation should be skipped for this package name.
	if h.pkgPath != "runtime" {
		return true
	}
	return false
}

// Given the Go vendoring conventions, return the package prefix of the vendored
// package. For example, given `my-app/vendor/github.com/sqreen/go-agent`,
// the function should return `my-app/vendor/`
func unvendorPackagePath(pkg string) (unvendored string) {
	return Unvendor(pkg)
}

func (h *defaultPackageInstrumentation) Instrument() (instrumented []*dst.File, err error) {
	h.instrumentedFiles = make(map[*dst.File][]*hookpoint)
	v := newDefaultPackageInstrumentationVisitor(h.pkgPath, h.instrumentedFiles)
	return h.packageInstrumentationHelper.instrument(v)
}

func (h *defaultPackageInstrumentation) writeHookList(hookList *os.File) (count int, err error) {
	for _, hooks := range h.instrumentedFiles {
		for _, hook := range hooks {
			if _, err = hookList.WriteString(fmt.Sprintf("%s\n", hook.descriptorFuncDecl.Name.Name)); err != nil {
				return count, err
			}
			count += 1
		}
	}
	return count, nil
}

func (h *defaultPackageInstrumentation) WriteExtraFiles() (extra []string, err error) {
	// Add the hook IDs to the hook list file.
	hookListFile, err := openHookListFile(h.hookListFilepath)
	if err != nil {
		return nil, err
	}
	defer hookListFile.Close()
	count, err := h.writeHookList(hookListFile)
	if err != nil {
		return nil, err
	}
	log.Printf("added %d hooks to the hook list\n", count)
	if h.pkgPath == "runtime" {

		rtExtensions := filepath.Join(h.packageBuildDir, "sqreen.go")
		if err := ioutil.WriteFile(rtExtensions, []byte(`package runtime

import _ "unsafe"

//go:nosplit
func Goid() int64 {
	return getg().goid
}

//go:nosplit
func Mid() uint64 {
	return getg().m.procid
}

func _ddog_runtime_execute(goID int64, tid uint64)

func _ddog_runtime_goexit(goID int64)

`), 0644); err != nil {
			return nil, err
		}
		return []string{rtExtensions}, nil
	}

	return nil, nil
}

// Create or append the hook list file in write-only.
func openHookListFile(hookListFilepath string) (*os.File, error) {
	return os.OpenFile(hookListFilepath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
}

func getHookListFilepath(dir string) string {
	return filepath.Join(dir, "sqreen-hooks.txt")
}
