// Command layoutgen writes layout_test.go: a table of sizes and field offsets
// that the Go mirrors of vmmdll.h structs must match.
//
// It asks clang for the real C layout (-fdump-record-layouts), reads the Go
// structs with go/ast and pairs fields by name. Run it from the repo root
// whenever vmmdll.h is updated:
//
//	go generate ./...
//
// Requirements: clang, and vmmdll.h plus leechcore.h in the include dir
// (libs/ by default). leechcore.h is at
// https://github.com/ufrisk/LeechCore/blob/master/includes/leechcore.h
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// mirror links a Go struct to the C struct it copies. member is set when the
// Go struct mirrors a named nested struct (e.g. VMMDLL_PROCESS_INFORMATION.win).
type mirror struct {
	goType, cType, member string
}

var mirrors = []mirror{
	{"kdeviceEntryInternal", "VMMDLL_MAP_KDEVICEENTRY", ""},
	{"kdeviceListInternal", "VMMDLL_MAP_KDEVICE", ""},
	{"kdriverEntryInternal", "VMMDLL_MAP_KDRIVERENTRY", ""},
	{"kdriverListInternal", "VMMDLL_MAP_KDRIVER", ""},
	{"kobjectEntryInternal", "VMMDLL_MAP_KOBJECTENTRY", ""},
	{"kobjectListInternal", "VMMDLL_MAP_KOBJECT", ""},
	{"vadExEntryInternal", "VMMDLL_MAP_VADEXENTRY", ""},
	{"vadExListInternal", "VMMDLL_MAP_VADEX", ""},
	{"pfnEntryInternal", "VMMDLL_MAP_PFNENTRY", ""},
	{"pfnListInternal", "VMMDLL_MAP_PFN", ""},
	{"vmEntryInternal", "VMMDLL_MAP_VMENTRY", ""},
	{"vmListInternal", "VMMDLL_MAP_VM", ""},
	{"physMemEntryInternal", "VMMDLL_MAP_PHYSMEMENTRY", ""},
	{"physMemListInternal", "VMMDLL_MAP_PHYSMEM", ""},
	{"poolEntryInternal", "VMMDLL_MAP_POOLENTRY", ""},
	{"poolListInternal", "VMMDLL_MAP_POOL", ""},
	{"WinProcessInfo", "VMMDLL_PROCESS_INFORMATION", "win"},
	{"ProcessInfo", "VMMDLL_PROCESS_INFORMATION", ""},
	{"moduleEntryInternal", "VMMDLL_MAP_MODULEENTRY", ""},
	{"moduleDebugInfoInternal", "VMMDLL_MAP_MODULEENTRY_DEBUGINFO", ""},
	{"moduleVersionInfoInternal", "VMMDLL_MAP_MODULEENTRY_VERSIONINFO", ""},
	{"moduleListInternal", "VMMDLL_MAP_MODULE", ""},
	{"threadEntryInternal", "VMMDLL_MAP_THREADENTRY", ""},
	{"threadListInternal", "VMMDLL_MAP_THREAD", ""},
	{"vadEntryInternal", "VMMDLL_MAP_VADENTRY", ""},
	{"vadListInternal", "VMMDLL_MAP_VAD", ""},
	{"handleEntryInternal", "VMMDLL_MAP_HANDLEENTRY", ""},
	{"handleListInternal", "VMMDLL_MAP_HANDLE", ""},
	{"eatEntryInternal", "VMMDLL_MAP_EATENTRY", ""},
	{"eatMapInternal", "VMMDLL_MAP_EAT", ""},
	{"iatThunkInternal", "VMMDLL_MAP_IATENTRY", "Thunk"},
	{"iatEntryInternal", "VMMDLL_MAP_IATENTRY", ""},
	{"iatMapInternal", "VMMDLL_MAP_IAT", ""},
	{"unloadedModuleEntryInternal", "VMMDLL_MAP_UNLOADEDMODULEENTRY", ""},
	{"unloadedModuleListInternal", "VMMDLL_MAP_UNLOADEDMODULE", ""},
	{"pteEntryInternal", "VMMDLL_MAP_PTEENTRY", ""},
	{"pteListInternal", "VMMDLL_MAP_PTE", ""},
	{"netAddrInternal", "VMMDLL_MAP_NETENTRY", "Src"},
	{"netEntryInternal", "VMMDLL_MAP_NETENTRY", ""},
	{"netListInternal", "VMMDLL_MAP_NET", ""},
	{"heapEntryInternal", "VMMDLL_MAP_HEAPENTRY", ""},
	{"heapSegmentInternal", "VMMDLL_MAP_HEAP_SEGMENTENTRY", ""},
	{"heapListInternal", "VMMDLL_MAP_HEAP", ""},
	{"heapAllocEntryInternal", "VMMDLL_MAP_HEAPALLOCENTRY", ""},
	{"heapAllocListInternal", "VMMDLL_MAP_HEAPALLOC", ""},
	{"registryHiveInfoInternal", "VMMDLL_REGISTRY_HIVE_INFORMATION", ""},
	{"ImageDataDirectory", "IMAGE_DATA_DIRECTORY", ""},
	{"ImageSectionHeader", "IMAGE_SECTION_HEADER", ""},
	{"ServiceStatus", "SERVICE_STATUS", ""},
	{"serviceEntryInternal", "VMMDLL_MAP_SERVICEENTRY", ""},
	{"serviceListInternal", "VMMDLL_MAP_SERVICE", ""},
	{"threadCallstackEntryInternal", "VMMDLL_MAP_THREAD_CALLSTACKENTRY", ""},
	{"threadCallstackInternal", "VMMDLL_MAP_THREAD_CALLSTACK", ""},
	{"userEntryInternal", "VMMDLL_MAP_USERENTRY", ""},
	{"userListInternal", "VMMDLL_MAP_USER", ""},
	{"vfsFileListBlobInternal", "VMMDLL_VFS_FILELISTBLOB", ""},
	{"vfsFileListExInfoInternal", "VMMDLL_VFS_FILELIST_EXINFO", ""},
	{"vfsFileListBlobEntryInternal", "VMMDLL_VFS_FILELISTBLOB_ENTRY", ""},
	{"winThunkInfoInternal", "VMMDLL_WIN_THUNKINFO_IAT", ""},
}

// aliases pair Go fields whose names can't be matched to C automatically.
var aliases = map[string]string{
	"ProcessInfo.SystemType":           "tpSystem",
	"ProcessInfo.ParentPID":            "dwPPID",
	"ProcessInfo.UserDTB":              "paDTB_UserOpt",
	"registryHiveInfoInternal.PathRaw": "uszHiveRootPath",
}

func main() {
	pkgDir := flag.String("pkg", ".", "directory of the Go package with the mirror structs")
	includeDir := flag.String("include", "libs", "directory with vmmdll.h and leechcore.h")
	out := flag.String("out", "layout_test.go", "output file")
	flag.Parse()
	log.SetFlags(0)

	header := filepath.Join(*includeDir, "vmmdll.h")
	version, err := headerVersion(header)
	if err != nil {
		log.Fatal(err)
	}
	recs, err := clangLayouts(*includeDir)
	if err != nil {
		log.Fatal(err)
	}
	goFields, err := goStructFields(*pkgDir)
	if err != nil {
		log.Fatal(err)
	}

	var b bytes.Buffer
	writeHeader(&b, version)
	unmatched := 0
	for _, m := range mirrors {
		rec, ok := findRecord(recs, m.cType)
		if !ok {
			log.Fatalf("C struct %s not found in clang output", m.cType)
		}
		fields, ok := goFields[m.goType]
		if !ok {
			log.Fatalf("Go struct %s not found in %s", m.goType, *pkgDir)
		}
		lay, err := rec.view(m.member)
		if err != nil {
			log.Fatalf("%s: %v", m.cType, err)
		}
		size := lay.size
		if lay.fam >= 0 {
			size = lay.fam
		}
		cName := m.cType
		if m.member != "" {
			cName += "." + m.member
		}
		fmt.Fprintf(&b, "\t{reflect.TypeFor[%s](), %q, %d, []cField{\n", m.goType, cName, size)
		type pair struct {
			goName, cName string
			off           int
		}
		var pairs []pair
		for _, f := range fields {
			c, ok := lay.match(m.goType, f)
			if !ok {
				unmatched++
				continue
			}
			pairs = append(pairs, pair{f, c.name, c.off})
		}
		sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].off < pairs[j].off })
		for _, p := range pairs {
			fmt.Fprintf(&b, "\t\t{%q, %q, %d},\n", p.goName, p.cName, p.off)
		}
		b.WriteString("\t}},\n")
	}
	b.WriteString(testFooter)

	src, err := format.Source(b.Bytes())
	if err != nil {
		log.Fatalf("format output: %v", err)
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s: %d structs (vmmdll.h %s), %d Go fields without a C name match (checked by size only)",
		*out, len(mirrors), version, unmatched)
}

func headerVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`Header Version:\s*(\S+)`).FindSubmatch(data)
	if m == nil {
		return "", fmt.Errorf("no 'Header Version' in %s", path)
	}
	return string(m[1]), nil
}

// cField is one line of clang's record layout dump.
type cField struct {
	off   int
	depth int
	name  string // empty for anonymous unions/structs
}

type record struct {
	size   int
	fields []cField
}

var (
	layoutLine = regexp.MustCompile(`^\s*(\d+)(?::[\d-]+)? \|( *)(.*)$`)
	sizeLine   = regexp.MustCompile(`\[sizeof=(\d+)`)
)

// clangLayouts compiles a file that takes sizeof of every mirrored struct and
// parses the record layouts clang prints for them.
func clangLayouts(includeDir string) (map[string]*record, error) {
	var c strings.Builder
	c.WriteString("#include \"vmmdll.h\"\nunsigned long sizes[] = {\n")
	for _, m := range mirrors {
		fmt.Fprintf(&c, "\tsizeof(%s),\n", m.cType)
	}
	c.WriteString("};\n")

	tmp, err := os.CreateTemp("", "layoutgen-*.c")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(c.String()); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	// -DMACOS selects the non-Windows typedefs in leechcore.h; they are
	// identical on Linux and give the same layouts as Windows x64.
	cmd := exec.Command("clang", "-DMACOS", "-I", includeDir, "-fsyntax-only",
		"-Xclang", "-fdump-record-layouts", tmp.Name())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	outData, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("clang: %v\n%s", err, stderr.String())
	}

	recs := map[string]*record{}
	var cur *record
	var curName string
	sc := bufio.NewScanner(bytes.NewReader(outData))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if m := layoutLine.FindStringSubmatch(line); m != nil {
			off, _ := strconv.Atoi(m[1])
			indent, rest := len(m[2]), strings.TrimRight(m[3], " ")
			if cur == nil {
				if indent == 1 {
					f := strings.Fields(rest)
					cur, curName = &record{}, f[len(f)-1]
				}
				continue
			}
			name := ""
			if i := strings.LastIndex(rest, " "); i >= 0 && !strings.HasSuffix(rest, ")") {
				name = rest[i+1:]
			}
			cur.fields = append(cur.fields, cField{off: off, depth: (indent - 1) / 2, name: name})
			continue
		}
		if m := sizeLine.FindStringSubmatch(line); m != nil && cur != nil {
			cur.size, _ = strconv.Atoi(m[1])
			if _, dup := recs[curName]; !dup {
				recs[curName] = cur
			}
			cur = nil
		}
	}
	return recs, sc.Err()
}

func findRecord(recs map[string]*record, cType string) (*record, bool) {
	for _, k := range []string{"td" + cType, "td_" + cType, "_" + cType, cType} {
		if r, ok := recs[k]; ok {
			return r, true
		}
	}
	return nil, false
}

type member struct {
	name string
	off  int
}

// layout is the flat view of one struct: its direct members (members of
// anonymous unions are promoted), size and flexible-array offset (-1 if none).
type layout struct {
	size    int
	fam     int
	byName  map[string]member
	byShort map[string][]member
}

func (r *record) view(nested string) (*layout, error) {
	fields, base, depth0, size := r.fields, 0, 0, r.size
	if nested != "" {
		idx := -1
		for i, f := range fields {
			if f.depth == 1 && f.name == nested {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("member %q not found", nested)
		}
		base, depth0 = fields[idx].off, 1
		rest := fields[idx+1:]
		end, next := len(rest), r.size
		for i, f := range rest {
			if f.depth <= 1 {
				end, next = i, f.off
				break
			}
		}
		fields, size = rest[:end], next-base
	}

	l := &layout{size: size, fam: -1, byName: map[string]member{}, byShort: map[string][]member{}}
	anon := map[int]bool{} // relative depths that are anonymous containers
	for _, f := range fields {
		rel := f.depth - depth0
		for d := range anon {
			if d >= rel {
				delete(anon, d)
			}
		}
		if rel != 1 && !anon[rel-1] {
			continue
		}
		if f.name == "" {
			anon[rel] = true
			continue
		}
		m := member{f.name, f.off - base}
		if _, ok := l.byName[strings.ToLower(f.name)]; !ok {
			l.byName[strings.ToLower(f.name)] = m
		}
		short := strings.ToLower(strings.TrimLeft(hungarian.ReplaceAllString(f.name, "$1"), "_"))
		l.byShort[short] = append(l.byShort[short], m)
	}
	if depth0 == 0 {
		l.fam = famOffset(fields)
	}
	return l, nil
}

// famOffset returns the offset of the trailing flexible array member
// (pMap[] or FileEntry[]), or -1 if the struct has none.
func famOffset(fields []cField) int {
	var last *cField
	for i := range fields {
		if fields[i].depth == 1 {
			last = &fields[i]
		}
	}
	if last != nil && (last.name == "pMap" || last.name == "FileEntry") {
		return last.off
	}
	return -1
}

// hungarian strips C type prefixes: dwVersion -> Version, vaPEB -> PEB.
var hungarian = regexp.MustCompile(`^[a-z]+([A-Z_])`)

func (l *layout) match(goType, goField string) (member, bool) {
	if alias, ok := aliases[goType+"."+goField]; ok {
		m, ok := l.byName[strings.ToLower(alias)]
		return m, ok
	}
	if m, ok := l.byName[strings.ToLower(goField)]; ok {
		return m, true
	}
	g := strings.TrimSuffix(goField, "Raw")
	if len(g) > 2 && strings.HasPrefix(g, "Is") && (g[2] >= 'A' && g[2] <= 'Z' || g[2] >= '0' && g[2] <= '9') {
		g = g[2:]
	}
	if c := l.byShort[strings.ToLower(g)]; len(c) == 1 {
		return c[0], true
	}
	return member{}, false
}

// goStructFields returns the named fields of every struct type in dir.
func goStructFields(dir string) (map[string][]string, error) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			var names []string
			for _, fl := range st.Fields.List {
				for _, id := range fl.Names {
					if id.Name != "_" {
						names = append(names, id.Name)
					}
				}
			}
			out[ts.Name.Name] = names
			return true
		})
	}
	return out, nil
}

func writeHeader(b *bytes.Buffer, version string) {
	fmt.Fprintf(b, `// Code generated by internal/cmd/layoutgen; DO NOT EDIT.

package memprocfs

import (
	"reflect"
	"testing"
	"unsafe"
)

// cLayout describes the C layout a Go struct must match byte for byte.
// Values come from vmmdll.h (Header Version %s) via clang -fdump-record-layouts
// on a 64-bit target. For list headers, size is the offset of the trailing
// flexible array (pMap[]), because ffi.FAM reads entries right after the Go struct.
type cLayout struct {
	typ    reflect.Type
	cName  string
	size   uintptr
	fields []cField
}

type cField struct {
	goName string
	cName  string
	offset uintptr
}

var cLayouts = []cLayout{
`, version)
}

const testFooter = `}

// TestCStructLayouts checks that every Go mirror of a vmmdll.h struct has the
// same size and field offsets as the C original. A mismatch means data is
// read from the wrong place, which tests on a real dump may not notice.
// Needs neither the native library nor a memory dump.
func TestCStructLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("expected layouts were generated for 64-bit targets")
	}
	for _, l := range cLayouts {
		t.Run(l.typ.Name(), func(t *testing.T) {
			if got := l.typ.Size(); got != l.size {
				t.Errorf("size of %s = %d, want %d (%s)", l.typ.Name(), got, l.size, l.cName)
			}
			for _, f := range l.fields {
				sf, ok := l.typ.FieldByName(f.goName)
				if !ok {
					t.Errorf("field %s.%s not found", l.typ.Name(), f.goName)
					continue
				}
				if sf.Offset != f.offset {
					t.Errorf("offset of %s.%s = %d, want %d (%s.%s)",
						l.typ.Name(), f.goName, sf.Offset, f.offset, l.cName, f.cName)
				}
			}
		})
	}
}
`
