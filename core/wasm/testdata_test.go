//go:build !no_wasm

package wasm

// Hand-rolled WASM binary fixtures for the package tests.
//
// wazero v1.11 does not ship a WAT compiler in tree; pre-built
// .wasm blobs are conventional in their repo too. Rather than
// check in binary fixtures we emit the modules as Go byte
// literals built at init time. The encoder below covers the
// MVP subset of the WASM binary format we need:
//
//   - module preamble + version
//   - type section with up to two function signatures
//   - function section
//   - export section (start function only)
//   - code section with a tiny instruction encoder
//
// This is NOT a general-purpose assembler — it produces exactly
// the three modules the tests need: a hello no-op, a trap
// module, and a fuel-hog. New test fixtures should extend the
// encoder rather than introduce a third-party dependency.

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// watCompile returns the binary WASM bytes corresponding to one
// of the three known fixture sources. Any other input fails the
// test loudly — there's no general WAT parser here.
func watCompile(src string) ([]byte, error) {
	switch src {
	case helloModuleWAT:
		return helloBinary, nil
	case trapModuleWAT:
		return trapBinary, nil
	case fuelHogModuleWAT:
		return fuelHogBinary, nil
	}
	return nil, errors.New("watCompile: unknown fixture (extend testdata_test.go)")
}

// --- WASM binary builder primitives ---------------------------------

const (
	wasmMagic     = 0x6d736100 // "\0asm"
	wasmVersion   = 0x00000001
	secType       = 1
	secFunc       = 3
	secMemory     = 5
	secExport     = 7
	secStart      = 8
	secCode       = 10
	valI32        = 0x7f
	exportFunc    = 0x00
	exportMem     = 0x02
	opEnd         = 0x0b
	opUnreachable = 0x00
	opLoop        = 0x03
	opBr          = 0x0c
	emptyBlock    = 0x40
)

// uleb writes a base-128 little-endian-unsigned integer.
func uleb(buf *bytes.Buffer, v uint32) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			buf.WriteByte(b)
			return
		}
		buf.WriteByte(b | 0x80)
	}
}

func vec(b *bytes.Buffer, items [][]byte) {
	uleb(b, uint32(len(items)))
	for _, it := range items {
		b.Write(it)
	}
}

func section(id byte, payload []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(id)
	uleb(&out, uint32(len(payload)))
	out.Write(payload)
	return out.Bytes()
}

// funcType encodes a function signature with no params and no
// returns OR with two i32 params and no returns.
func funcType(numParams int) []byte {
	var b bytes.Buffer
	b.WriteByte(0x60) // func
	uleb(&b, uint32(numParams))
	for i := 0; i < numParams; i++ {
		b.WriteByte(valI32)
	}
	uleb(&b, 0) // no results
	return b.Bytes()
}

// funcBody wraps an instruction stream with the conventional
// "0 locals" prefix and trailing `end`. Returns the size-
// prefixed body suitable for the code section.
func funcBody(instrs []byte) []byte {
	var inner bytes.Buffer
	uleb(&inner, 0) // 0 local groups
	inner.Write(instrs)
	inner.WriteByte(opEnd)
	var out bytes.Buffer
	uleb(&out, uint32(inner.Len()))
	out.Write(inner.Bytes())
	return out.Bytes()
}

// preamble writes the magic + version header.
func preamble() []byte {
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, uint32(wasmMagic))
	binary.Write(&out, binary.LittleEndian, uint32(wasmVersion))
	return out.Bytes()
}

// nameBytes writes a length-prefixed name.
func nameBytes(name string) []byte {
	var b bytes.Buffer
	uleb(&b, uint32(len(name)))
	b.WriteString(name)
	return b.Bytes()
}

// buildModule assembles a one-or-two-function module:
//   - func 0: `_start` (no params, no returns)
//   - optional func 1: `water_transport_dial_target` (i32, i32)
//
// instr0 is the body of `_start`; instr1 is the body of the
// optional dial-target. Pass nil to omit the second function.
func buildModule(instr0, instr1 []byte) []byte {
	// Type section
	types := [][]byte{funcType(0)} // type 0: () -> ()
	if instr1 != nil {
		types = append(types, funcType(2)) // type 1: (i32,i32) -> ()
	}
	var typePayload bytes.Buffer
	vec(&typePayload, types)

	// Function section: list of type indices for each defined func.
	var funcPayload bytes.Buffer
	if instr1 != nil {
		uleb(&funcPayload, 2) // 2 funcs
		funcPayload.WriteByte(0)
		funcPayload.WriteByte(1)
	} else {
		uleb(&funcPayload, 1)
		funcPayload.WriteByte(0)
	}

	// Memory section: 1 page minimum, no maximum.
	var memPayload bytes.Buffer
	uleb(&memPayload, 1) // 1 memory
	memPayload.WriteByte(0x00)
	uleb(&memPayload, 1)

	// Export section: `_start` + `memory` (+ optional dial).
	var exportPayload bytes.Buffer
	exportCount := uint32(2)
	if instr1 != nil {
		exportCount = 3
	}
	uleb(&exportPayload, exportCount)
	exportPayload.Write(nameBytes("_start"))
	exportPayload.WriteByte(exportFunc)
	uleb(&exportPayload, 0)
	exportPayload.Write(nameBytes("memory"))
	exportPayload.WriteByte(exportMem)
	uleb(&exportPayload, 0)
	if instr1 != nil {
		exportPayload.Write(nameBytes("water_transport_dial_target"))
		exportPayload.WriteByte(exportFunc)
		uleb(&exportPayload, 1)
	}

	// Code section
	codes := [][]byte{funcBody(instr0)}
	if instr1 != nil {
		codes = append(codes, funcBody(instr1))
	}
	var codePayload bytes.Buffer
	vec(&codePayload, codes)

	var out bytes.Buffer
	out.Write(preamble())
	out.Write(section(secType, typePayload.Bytes()))
	out.Write(section(secFunc, funcPayload.Bytes()))
	out.Write(section(secMemory, memPayload.Bytes()))
	out.Write(section(secExport, exportPayload.Bytes()))
	out.Write(section(secCode, codePayload.Bytes()))
	return out.Bytes()
}

var (
	// hello: empty `_start`. No second function → Dial returns
	// OutcomeOK by the "instantiate-time dial" convention.
	helloBinary = buildModule(nil, nil)

	// trap: `water_transport_dial_target` is `unreachable;
	// end`.
	trapBinary = buildModule(nil, []byte{opUnreachable})

	// fuel-hog: `water_transport_dial_target` is `loop $L; br
	// $L; end`. Branches to the loop unconditionally.
	fuelHogBinary = buildModule(nil, []byte{
		opLoop, emptyBlock,
		opBr, 0,
		opEnd,
	})
)
