// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package main

import (
	"fmt"
	"go/printer"
	"go/token"
	"io"
	"strings"

	"github.com/dave/dst"
	"github.com/dave/dst/decorator"
)

const (
	sqreenUnsafePackageName = `_sqreen_unsafe_`
)

func newVarDecl(ident string, typ dst.Expr) (*dst.GenDecl, *dst.ValueSpec) {
	varSpec := &dst.ValueSpec{
		Names: []*dst.Ident{
			dst.NewIdent(ident),
		},
		Type: typ,
	}
	return &dst.GenDecl{
		Tok: token.VAR,
		Specs: []dst.Spec{
			varSpec,
		},
	}, varSpec
}

func newLinkTimeForwardFuncDecl(ident string, ftype *dst.FuncType) *dst.FuncDecl {
	return &dst.FuncDecl{
		Decs: dst.FuncDeclDecorations{
			NodeDecs: dst.NodeDecs{
				Before: dst.NewLine,
				Start: dst.Decorations{
					fmt.Sprintf("//go:linkname %[1]s %[1]s\n", ident),
				},
			},
		},
		Name: dst.NewIdent(ident),
		Type: ftype,
	}
}

// Return expression for type `_sqreen_unsafe_.Pointer`
func newSqreenUnsafePointerType() dst.Expr {
	return newQualifiedIdent(sqreenUnsafePackageName, "Pointer")
}

// Return qualified identifier for `pkgName.ident`
func newQualifiedIdent(pkgName, ident string) dst.Expr {
	return &dst.SelectorExpr{X: dst.NewIdent(pkgName), Sel: dst.NewIdent(ident)}
}

// Return expression for `&ident`
func newIdentAddressExpr(ident *dst.Ident) dst.Expr {
	return &dst.UnaryExpr{Op: token.AND, X: ident}
}

// Return expression for `interface{}`
func newEmptyInterfaceType() dst.Expr {
	return &dst.InterfaceType{Methods: &dst.FieldList{Opening: true, Closing: true}}
}

// Return expression for `expr.sel`
func newSelectorExpr(expr dst.Expr, sel string) *dst.SelectorExpr {
	return &dst.SelectorExpr{
		X:   expr,
		Sel: dst.NewIdent(sel),
	}
}

// Return method value expression `(<receiver type>).<method name>` for
// the given function declaration.
func newMethodValueExpr(fn *dst.FuncDecl) dst.Expr {
	t := fn.Recv.List[0].Type
	return newSelectorExpr(&dst.ParenExpr{X: t}, fn.Name.Name)
}

// Return the value expression for the given function declaration.
// It can be either a method or a function value.
func newFunctionValueExpr(fn *dst.FuncDecl) (v dst.Expr) {
	if fn.Recv == nil {
		v = fn.Name
	} else {
		v = newMethodValueExpr(fn)
	}
	return dst.Clone(v).(dst.Expr)
}

// Return the expression to cast the given value to the given typ
// `(<typ>)(<val>)`.
func newCastValueExpr(typ dst.Expr, val dst.Expr) dst.Expr {
	return &dst.CallExpr{Fun: typ, Args: []dst.Expr{val}}
}

func writeFile(file *dst.File, w io.Writer) error {
	fset, af, err := decorator.RestoreFile(file)
	if err != nil {
		return err
	}
	return printer.Fprint(w, fset, af)
}

// Unvendor returns the given symbol name without the vendor directory prefix
// if any. For example, given `my-app/vendor/github.com/sqreen/go-agent`,
// the function returns `github.com/sqreen/go-agent`
func Unvendor(symbol string) (unvendored string) {
	vendorDir := "/vendor/"
	i := strings.Index(symbol, vendorDir)
	if i == -1 {
		return symbol
	}
	return symbol[i+len(vendorDir):]
}
