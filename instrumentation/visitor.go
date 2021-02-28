// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package main

import (
	"fmt"
	"github.com/dave/dst"
	"github.com/dave/dst/dstutil"
)

type instrumentationVisitorFace interface {
	instrument(root *dst.Package) (instrumented []*dst.File)
}

type defaultPackageInstrumentationVisitor struct {
	// Instrumentation statistics of the currently instrumented package.
	stats instrumentationStats
	// Package path being instrumented. Used to generate unique hook names
	// prefixed by the package path.
	pkgPath string
	// False when the first file is being instrumented in order to add
	// metadata that must appear once.
	fileMetadataOnce bool
	// List of hookpoints in the current file being instrumented.
	instrumented []*hookpoint
	// Map of instrumented files along with there hookpoints
	instrumentedHooks map[*dst.File][]*hookpoint
	// Slice of instrumented files
	instrumentedFiles []*dst.File
	// Hook descriptor type declaration node. It will be added to the file
	// metadata.
	hookDescriptorTypeIdent string
	// The hook descriptor value initializer used by the hook descriptor function
	// in order to create a new descriptor value.
	newHookDescriptorValueInitializer hookDescriptorValueInitializer
	// The hook descriptor type declaration added once per instrumented package
	// and used by hook descriptor functions to return a value of that type.
	hookDescriptorTypeDecl *dst.GenDecl
}

type instrumentationStats struct {
	ignored      []string
	instrumented []string
}

func (s *instrumentationStats) addIgnored(funcDecl *dst.FuncDecl) {
	s.ignored = append(s.ignored, funcDecl.Name.Name)
}

func (s *instrumentationStats) addInstrumented(funcDecl *dst.FuncDecl) {
	s.instrumented = append(s.instrumented, funcDecl.Name.Name)
}

func newDefaultPackageInstrumentationVisitor(pkgPath string, instrumentedFiles map[*dst.File][]*hookpoint) *defaultPackageInstrumentationVisitor {
	hookDescriptorTypeDecl, hookDescriptorTypeSpec, newDescriptorValueInitializer := newHookDescriptorType()
	hookDescriptorTypeIdent := hookDescriptorTypeSpec.Name.Name
	return &defaultPackageInstrumentationVisitor{
		pkgPath:                           pkgPath,
		instrumentedHooks:                 instrumentedFiles,
		hookDescriptorTypeIdent:           hookDescriptorTypeIdent,
		hookDescriptorTypeDecl:            hookDescriptorTypeDecl,
		newHookDescriptorValueInitializer: newDescriptorValueInitializer,
	}
}

func (v *defaultPackageInstrumentationVisitor) instrumentFuncDeclPre(funcDecl *dst.FuncDecl) {
	if funcDecl.Name.String() != "execute" {
		v.stats.addIgnored(funcDecl)
		return
	}

	hook := newHookpoint(v.pkgPath, funcDecl, v.hookDescriptorTypeIdent, v.newHookDescriptorValueInitializer)
	v.instrumented = append(v.instrumented, hook)

	newEnd := append([]dst.Stmt{hook.instrumentationStmt}, funcDecl.Body.List[len(funcDecl.Body.List) - 1])
	funcDecl.Body.List = append(funcDecl.Body.List[:len(funcDecl.Body.List) - 1], newEnd...)
}

func (v *defaultPackageInstrumentationVisitor) instrument(root *dst.Package) (instrumented []*dst.File) {
	dstutil.Apply(root, v.instrumentPre, v.instrumentPost)
	fmt.Println(len(v.instrumentedFiles))
	return v.instrumentedFiles
}

func (v *defaultPackageInstrumentationVisitor) instrumentPre(cursor *dstutil.Cursor) bool {
	switch node := cursor.Node().(type) {
	case *dst.FuncDecl:
		v.instrumentFuncDeclPre(node)
		// Note that we don't add the file metadata here in order to avoid to
		// infinite traversal because of adding new AST nodes while visiting it.

		// No need to go deeper than function declarations
		return false
	}
	return true
}

func (v *defaultPackageInstrumentationVisitor) instrumentPost(cursor *dstutil.Cursor) bool {
	switch node := cursor.Node().(type) {
	case *dst.File:
		v.instrumentFilePost(node)
	}
	return true
}

func (v *defaultPackageInstrumentationVisitor) instrumentFilePost(file *dst.File) {
	if len(v.instrumented) == 0 {
		// Nothing got instrumented
		return
	}

	// Add the list of hooks of this file node
	v.instrumentedHooks[file] = v.instrumented
	v.instrumented = nil

	// Add the file node in the list of instrumented files
	v.instrumentedFiles = append(v.instrumentedFiles, file)
}
