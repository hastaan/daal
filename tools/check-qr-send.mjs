#!/usr/bin/env node
// check-qr-send.mjs — the automated half of OWNER QR-SEND.
//
// A camera is the one thing this gate cannot have, so it tests
// everything up to the glass, and it tests it against the REAL other
// implementations rather than against itself:
//
//   1. The vendored QR encoder (client-ui/src/qr/qrcodegen.ts) is
//      compared MODULE FOR MODULE against github.com/skip2/go-qrcode —
//      an independent encoder already vendored in the Go module cache
//      for bundle/go. Same input, same symbol, or this fails.
//   2. Its capacity tables are re-derived from that library's version
//      table, so a typo in 320 hand-entered numbers cannot survive.
//   3. The frame sequencing (client-ui/src/qr/fountainStream.ts) is
//      driven with frames from the REAL Go LT codec
//      (bundle/go/fountain), and the exact sequence of frames the
//      screen would display — with frames randomly DROPPED, because a
//      camera misses frames — is fed back into the REAL Go decoder,
//      which must reconstruct the pack byte for byte.
//   4. The `2k + 32` frames-per-pass constant the UI shows the user is
//      re-measured against that decoder instead of being trusted.
//   5. A pack far larger than any real .sbp is pushed through the
//      buffer to prove the screen survives it on a fixed memory
//      budget.
//
// Requires node + go. Both are already required by ./daal test, and a
// gate that silently skips itself protects nothing, so a missing
// toolchain is exit 2, not a pass.

import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const UI = join(ROOT, 'client-ui');
const ESBUILD = join(UI, 'node_modules', '.bin', 'esbuild');
const GO_MODULE_DIR = join(ROOT, 'bundle', 'go');

let failures = 0;
let checks = 0;
function ok(name) {
    checks++;
    console.log(`  ✓ ${name}`);
}
function bad(name, detail) {
    checks++;
    failures++;
    console.log(`  ✗ ${name}`);
    if (detail) console.log(`      ${String(detail).split('\n').join('\n      ')}`);
}
function assert(cond, name, detail) {
    if (cond) ok(name);
    else bad(name, detail);
}
function section(title) {
    console.log(`\n${title}`);
}

function die(msg) {
    console.error(`[check-qr-send] FAIL: ${msg}`);
    process.exit(2);
}

if (!existsSync(ESBUILD)) {
    die(
        `esbuild not found at ${ESBUILD}. Run \`npm install\` in client-ui — ` +
            `this gate compiles the TypeScript under test and cannot run without it.`,
    );
}
const goProbe = spawnSync('go', ['version'], { encoding: 'utf8' });
if (goProbe.status !== 0) {
    die('`go` is not on PATH; this gate compares against the Go QR and fountain codecs.');
}

const work = mkdtempSync(join(tmpdir(), 'daal-qrcheck-'));
process.on('exit', () => {
    try {
        rmSync(work, { recursive: true, force: true });
    } catch {
        /* best effort */
    }
});

// ---- build the TS under test into a plain ESM module ---------------

const entry = join(work, 'entry.ts');
writeFileSync(
    entry,
    `export * as qr from ${JSON.stringify(join(UI, 'src/qr/qrcodegen.ts'))};\n` +
        `export * as fs from ${JSON.stringify(join(UI, 'src/qr/fountainStream.ts'))};\n` +
        `export * as paint from ${JSON.stringify(join(UI, 'src/qr/paint.ts'))};\n`,
);
const bundlePath = join(work, 'qr.mjs');
execFileSync(ESBUILD, [
    entry,
    '--bundle',
    '--format=esm',
    '--platform=node',
    `--outfile=${bundlePath}`,
    '--log-level=warning',
]);
const { qr, fs: fstream, paint } = await import(bundlePath);

// ---- the Go side ---------------------------------------------------
//
// Written to a temp dir and run with `go run` from bundle/go so it
// compiles against that module's deps (daal/bundle-go/fountain and
// github.com/skip2/go-qrcode, both already required there). It is a
// test fixture, so it lives here rather than adding a binary to the
// production tree.

const GO_HELPER = String.raw`
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"

	"daal/bundle-go/fountain"
	qrcode "github.com/skip2/go-qrcode"
)

func payloadFor(size int, seed int64) []byte {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, size)
	r.Read(b)
	return b
}

func main() {
	switch os.Args[1] {

	// emit <size> <blockSize> <frames> <seed>
	// Mirrors the JSON-line output of 'daal-deploy qr-fountain'.
	case "emit":
		size, _ := strconv.Atoi(os.Args[2])
		bs, _ := strconv.Atoi(os.Args[3])
		n, _ := strconv.Atoi(os.Args[4])
		seed, _ := strconv.ParseInt(os.Args[5], 10, 64)
		payload := payloadFor(size, seed)
		sum := sha256.Sum256(payload)
		w := bufio.NewWriter(os.Stdout)
		defer w.Flush()
		hdr, _ := json.Marshal(map[string]any{"payload_sha256": hex.EncodeToString(sum[:]), "size": size})
		fmt.Fprintln(w, string(hdr))
		enc := fountain.NewEncoder(payload, bs, seed)
		for i := 0; i < n; i++ {
			line, _ := json.Marshal(map[string]any{
				"i": i, "k": enc.SourceBlocks(),
				"frame_b64": base64.RawURLEncoding.EncodeToString(enc.NextFrame()),
			})
			fmt.Fprintln(w, string(line))
		}

	// decode <expected_sha256_hex>  (base64url frames on stdin, one per line)
	case "decode":
		want := os.Args[2]
		dec := fountain.NewDecoder()
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		n := 0
		for sc.Scan() {
			line := sc.Text()
			if line == "" {
				continue
			}
			raw, err := base64.RawURLEncoding.DecodeString(line)
			if err != nil {
				fmt.Printf("ERR bad base64 on frame %d: %v\n", n, err)
				os.Exit(1)
			}
			n++
			out, done, err := dec.Add(raw)
			if err != nil {
				fmt.Printf("ERR decoder rejected frame %d: %v\n", n, err)
				os.Exit(1)
			}
			if done {
				sum := sha256.Sum256(out)
				if hex.EncodeToString(sum[:]) != want {
					fmt.Printf("ERR decoded %d bytes but hash mismatch\n", len(out))
					os.Exit(1)
				}
				fmt.Printf("OK %d\n", n)
				return
			}
		}
		got, tot := dec.Progress()
		fmt.Printf("INCOMPLETE %d frames, %d/%d blocks\n", n, got, tot)
		os.Exit(1)

	// overhead <size> <blockSize> <trials> — prints "k worst median",
	// the frames a lossless receiver needed to finish.
	case "overhead":
		size, _ := strconv.Atoi(os.Args[2])
		bs, _ := strconv.Atoi(os.Args[3])
		trials, _ := strconv.Atoi(os.Args[4])
		worst := 0
		k := 0
		all := []int{}
		for t := 0; t < trials; t++ {
			payload := payloadFor(size, int64(t)*7919+int64(size))
			enc := fountain.NewEncoder(payload, bs, int64(t)*104729+int64(bs))
			k = enc.SourceBlocks()
			dec := fountain.NewDecoder()
			n := 0
			for {
				n++
				_, done, err := dec.Add(enc.NextFrame())
				if err != nil {
					fmt.Println("ERR", err)
					os.Exit(1)
				}
				if done {
					break
				}
				if n > 1000000 {
					fmt.Println("ERR no decode")
					os.Exit(1)
				}
			}
			if n > worst {
				worst = n
			}
			all = append(all, n)
		}
		sort.Ints(all)
		fmt.Printf("%d %d %d\n", k, worst, all[len(all)/2])

	// qr <ecc L|M|Q|H> — reads one payload per line on stdin, prints
	// "<version> <rowbits...>" per input using skip2/go-qrcode.
	case "qr":
		var lvl qrcode.RecoveryLevel
		switch os.Args[2] {
		case "L":
			lvl = qrcode.Low
		case "M":
			lvl = qrcode.Medium
		case "Q":
			lvl = qrcode.High
		case "H":
			lvl = qrcode.Highest
		}
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		w := bufio.NewWriter(os.Stdout)
		defer w.Flush()
		for sc.Scan() {
			text := sc.Text()
			q, err := qrcode.New(text, lvl)
			if err != nil {
				fmt.Fprintln(w, "ERR", err)
				continue
			}
			bm := q.Bitmap()
			total := len(bm)
			// Strip the quiet zone; the symbol is 17+4v modules wide.
			var side, border int
			for v := 1; v <= 40; v++ {
				s := 17 + 4*v
				if (total-s)%2 == 0 && total-s >= 0 && (total-s)/2 >= 1 && (total-s)/2 <= 8 {
					side = s
					border = (total - s) / 2
					if border == 4 {
						break
					}
				}
			}
			out := make([]byte, 0, side*side+8)
			for y := 0; y < side; y++ {
				for x := 0; x < side; x++ {
					if bm[y+border][x+border] {
						out = append(out, '1')
					} else {
						out = append(out, '0')
					}
				}
			}
			fmt.Fprintf(w, "%d %s\n", (side-17)/4, string(out))
		}
	}
}
`;
const helperPath = join(work, 'qrcheck_helper.go');
writeFileSync(helperPath, GO_HELPER);

function go(args, input) {
    const r = spawnSync('go', ['run', helperPath, ...args], {
        cwd: GO_MODULE_DIR,
        input,
        encoding: 'utf8',
        maxBuffer: 256 * 1024 * 1024,
    });
    if (r.status !== 0) {
        die(`go helper ${args.join(' ')} failed:\n${r.stderr || r.stdout}`);
    }
    return r.stdout;
}

// =====================================================================
section('1. Pinned geometry — every frame is the same symbol');

assert(fstream.QR_FRAME_BYTES === 108, 'fountain frame is 108 bytes (12 header + 96 payload)');
assert(fstream.QR_FRAME_CHARS === 144, 'base64url frame is 144 characters', fstream.QR_FRAME_CHARS);
{
    const sample = 'a'.repeat(fstream.QR_FRAME_CHARS);
    const code = qr.encodeText(sample, fstream.QR_ECC);
    assert(
        code.version === fstream.QR_VERSION,
        `a full frame auto-selects version ${fstream.QR_VERSION} at ECC ${fstream.QR_ECC}`,
        `got ${code.version}`,
    );
    assert(code.size === 57, 'symbol is 57x57 modules', code.size);
    const headroom = qr.byteModeCapacity(fstream.QR_VERSION, fstream.QR_ECC) - fstream.QR_FRAME_CHARS;
    assert(headroom >= 0 && headroom < 16, `version ${fstream.QR_VERSION} headroom is ${headroom} chars`);
    let threw = false;
    try {
        fstream.assertGeometry();
    } catch (e) {
        threw = true;
        bad('assertGeometry()', e.message);
    }
    if (!threw) ok('assertGeometry() agrees at module load');
}

// =====================================================================
section('2. Capacity tables re-derived from skip2/go-qrcode');
{
    // The Go module cache holds the library's own version table. Parse
    // it and compare every one of the 160 (version, level) pairs.
    let versionGo = null;
    const modBase = spawnSync('go', ['env', 'GOMODCACHE'], { encoding: 'utf8' }).stdout.trim();
    if (modBase) {
        const dirs = spawnSync('sh', ['-c', `ls -d ${modBase}/github.com/skip2/go-qrcode*/version.go 2>/dev/null | head -1`], {
            encoding: 'utf8',
        }).stdout.trim();
        if (dirs) versionGo = dirs;
    }
    if (!versionGo) {
        bad('skip2 version.go located in the module cache', `GOMODCACHE=${modBase}`);
    } else {
        const src = readFileSync(versionGo, 'utf8');
        const body = src.slice(src.indexOf('versions = []qrCodeVersion{'));
        const re = /\{\s*(\d+),\s*(Low|Medium|High|Highest),\s*(\w+),\s*\[\]block\{([\s\S]*?)\},\s*(\d+),\s*\}/g;
        const LV = { Low: 'L', Medium: 'M', High: 'Q', Highest: 'H' };
        let m;
        let compared = 0;
        let mismatch = null;
        while ((m = re.exec(body)) != null) {
            const version = +m[1];
            const ecl = LV[m[2]];
            const groups = [];
            const bre = /\{\s*(\d+),\s*(\d+),\s*(\d+),\s*\}/g;
            let b;
            while ((b = bre.exec(m[4])) != null) {
                groups.push({ n: +b[1], total: +b[2], data: +b[3] });
            }
            const theirData = groups.reduce((a, g) => a + g.n * g.data, 0);
            const mine = qr.numDataCodewords(version, ecl);
            compared++;
            if (mine !== theirData && !mismatch) {
                mismatch = `version ${version} ECC ${ecl}: mine ${mine}, skip2 ${theirData}`;
            }
        }
        assert(compared === 160, 'parsed all 160 (version, level) pairs', `got ${compared}`);
        assert(mismatch === null, 'every data-codeword count matches skip2', mismatch);
    }
}

// =====================================================================
section('3. Finished symbols compared module-for-module with skip2');
{
    // Random byte-mode payloads across the whole version range, plus
    // the exact 144-char shape this app ships.
    const rnd = (() => {
        let s = 12345;
        return () => {
            s = (s * 1103515245 + 12345) & 0x7fffffff;
            return s / 0x7fffffff;
        };
    })();
    // Lowercase and underscore only, and that restriction is the
    // point of the comparison rather than a dodge. skip2 runs a
    // segment optimiser: given a run of digits or capitals it will
    // emit a mixed byte + alphanumeric symbol, which this encoder
    // deliberately never does (see qrcodegen.ts — one mode, tested,
    // rather than three, of which two nothing takes). Both symbols are
    // valid QR codes; they are simply not the same symbol, so a
    // module-for-module comparison over such a payload would be
    // comparing two different legal answers. Neither lowercase letters
    // nor `_` exist in QR's alphanumeric alphabet, so on these
    // payloads both encoders are pinned to single-segment byte mode
    // and any difference is a real defect.
    //
    // Real base64url frames DO contain capitals and digits, and they
    // are covered by section 4, which decodes them with jsQR — the
    // same scanner the receiving half of this wave uses.
    const ALPHABET = 'abcdefghijklmnopqrstuvwxyz_';
    const randomText = (n) => {
        let out = '';
        for (let i = 0; i < n; i++) out += ALPHABET[Math.floor(rnd() * ALPHABET.length)];
        return out;
    };

    for (const ecl of ['L', 'M', 'Q', 'H']) {
        const lengths = [1, 7, 16, 32, 64, 100, 144, 144, 144, 200, 300, 500, 800, 1200];
        const payloads = lengths.map((n) => randomText(n));
        const out = go(['qr', ecl], payloads.join('\n') + '\n').trim().split('\n');
        let versionOk = 0;
        let exactOk = 0;
        let maskAgree = 0;
        let firstFail = null;
        for (let i = 0; i < payloads.length; i++) {
            const [vStr, bits] = out[i].split(' ');
            const theirVersion = +vStr;
            const mine = qr.encodeText(payloads[i], ecl);
            if (mine.version !== theirVersion) {
                if (!firstFail) {
                    firstFail = `len ${payloads[i].length}: version mine ${mine.version} vs skip2 ${theirVersion}`;
                }
                continue;
            }
            versionOk++;
            const mineBits = Array.from(mine.modules).join('');
            if (mineBits === bits) {
                exactOk++;
                maskAgree++;
                continue;
            }
            // Same symbol, different mask choice, is still a correct QR
            // code: require an exact match at one of the eight masks so
            // that codewords, ECC, interleaving, placement, format and
            // version bits are all proven identical.
            let matched = -1;
            for (let m = 0; m < 8; m++) {
                const forced = qr.encodeText(payloads[i], ecl, theirVersion, m);
                if (Array.from(forced.modules).join('') === bits) {
                    matched = m;
                    break;
                }
            }
            if (matched >= 0) exactOk++;
            else if (!firstFail) firstFail = `len ${payloads[i].length} ECC ${ecl}: no mask reproduces skip2's symbol`;
        }
        assert(versionOk === payloads.length, `ECC ${ecl}: version selection matches skip2 on ${payloads.length} payloads`, firstFail);
        assert(exactOk === payloads.length, `ECC ${ecl}: every symbol reproduced module-for-module`, firstFail);
        // Mask choice is NOT asserted. Both encoders pick the
        // lowest-penalty mask, but skip2 scores the penalty over a grid
        // that includes the quiet zone while this one scores the symbol
        // as ISO/IEC 18004 defines it, so the two legitimately differ on
        // some payloads. Any of the eight masks is a valid QR code and
        // the exact-match test above already proves everything under the
        // mask is identical.
        console.log(`    · ECC ${ecl}: mask choice happened to agree on ${maskAgree}/${payloads.length} (informational)`);
    }
}

// =====================================================================
section('4. Real frames from the real codec, through the real screen buffer');

function emitFrames(size, blockSize, n, seed) {
    const lines = go(['emit', String(size), String(blockSize), String(n), String(seed)])
        .trim()
        .split('\n');
    const header = JSON.parse(lines[0]);
    return { sha: header.payload_sha256, frames: lines.slice(1).map((l) => JSON.parse(l)) };
}

// A pack at the top of the size range specs/sbpx-envelope-v1.md gives
// for a real .sbp ("typically 12-18 KB").
const PACK = 18 * 1024;
{
    const k = Math.ceil(PACK / fstream.QR_BLOCK_SIZE);
    const perPass = fstream.framesPerPass(k);
    const { sha, frames } = emitFrames(PACK, fstream.QR_BLOCK_SIZE, perPass + fstream.BATCH_FRAMES, 4242);

    assert(frames.every((f) => f.frame_b64.length === fstream.QR_FRAME_CHARS), 'every emitted frame is exactly 144 chars');
    assert(frames.every((f) => f.k === k), `every frame reports k=${k}`);

    // Every frame encodes at the pinned version — the property the
    // receiving camera depends on.
    let versions = new Set();
    for (const f of frames.slice(0, 400)) {
        versions.add(qr.encodeText(f.frame_b64, fstream.QR_ECC).version);
    }
    assert(versions.size === 1 && versions.has(fstream.QR_VERSION), `400 real frames all encode at version ${fstream.QR_VERSION}`, [...versions].join(','));

    // The closest thing to a camera that fits in a gate: render the
    // symbols this screen draws and read them back with jsQR — the
    // scanner the receiving half of this wave uses. A pass here means
    // the sender and the receiver agree about the bytes, and the only
    // untested link left is the optics.
    {
        let jsQR = null;
        try {
            const require = createRequire(join(UI, 'package.json'));
            const mod = require('jsqr');
            jsQR = mod.default ?? mod;
        } catch {
            jsQR = null;
        }
        if (!jsQR) {
            bad(
                'jsQR round-trip',
                'jsqr is not installed in client-ui/node_modules; the sender/receiver ' +
                    'byte agreement is UNVERIFIED in this run. Run npm install.',
            );
        } else {
            // Painted through the SAME function the canvas calls, so
            // the quiet zone, the integer module size and the fixed
            // black-on-white are covered here too, not just the encoder.
            const SCALE = 4; // device pixels per module in the synthetic image
            const w = paint.paintedModules() * SCALE;
            let decoded = 0;
            const sample = frames.slice(0, 30);
            for (const f of sample) {
                const img = new Uint8ClampedArray(w * w * 4).fill(255);
                const surface = {
                    fillStyle: '#000000',
                    fillRect(x0, y0, ww, hh) {
                        const v = this.fillStyle === '#000000' ? 0 : 255;
                        for (let yy = y0; yy < y0 + hh; yy++) {
                            for (let xx = x0; xx < x0 + ww; xx++) {
                                const p = (yy * w + xx) * 4;
                                img[p] = v;
                                img[p + 1] = v;
                                img[p + 2] = v;
                                img[p + 3] = 255;
                            }
                        }
                    },
                };
                paint.paintFrame(surface, f.frame_b64, SCALE);
                const res = jsQR(img, w, w);
                if (res && res.data === f.frame_b64) decoded++;
            }
            assert(
                decoded === sample.length,
                `jsQR read back ${decoded}/${sample.length} rendered frames, character for character`,
            );
        }
    }

    // Drive the buffer the way the screen does: frames arrive in a
    // burst per `wizard_qr_render` batch, the display pulls one per
    // tick, and the next batch is requested at the low-water mark.
    const stream = new fstream.FrameStream();
    let fed = 0;
    const feedBatch = () => {
        for (let i = 0; i < fstream.BATCH_FRAMES && fed < frames.length; i++) {
            stream.push(frames[fed++]);
        }
    };
    feedBatch();
    const shown = [];
    let batches = 1;
    for (let tick = 0; tick < perPass; tick++) {
        if (stream.needsMore && fed < frames.length) {
            feedBatch();
            batches++;
        }
        const f = stream.next();
        if (f === null) {
            bad('display never starves', `starved at tick ${tick}`);
            break;
        }
        shown.push(f);
    }
    assert(shown.length === perPass, `one pass showed ${perPass} frames (k=${k})`);
    assert(new Set(shown).size === shown.length, 'a single pass never repeats a frame while fresh ones remain');
    assert(stream.pass === 1 && stream.positionInPass === perPass, `progress counter ends the pass at ${perPass}/${perPass}, pass 1`);
    assert(stream.passComplete, 'passComplete flips exactly at the end of the pass');
    assert(batches > 1 && batches <= Math.ceil(perPass / fstream.BATCH_FRAMES) + 1, `prefetched ${batches} batches, no runaway`);

    // The camera is the lossy part. Drop frames at random and require
    // the REAL decoder to still finish inside one pass.
    for (const loss of [0, 0.15, 0.3]) {
        let seed = 99;
        const rand = () => {
            seed = (seed * 1103515245 + 12345) & 0x7fffffff;
            return seed / 0x7fffffff;
        };
        const kept = shown.filter(() => rand() >= loss);
        const res = go(['decode', sha], kept.join('\n') + '\n').trim();
        assert(
            res.startsWith('OK'),
            `one pass decodes with ${Math.round(loss * 100)}% of frames missed (${kept.length} seen)`,
            res,
        );
    }
}

// =====================================================================
section('5. The frames-per-pass promise, re-measured against the decoder');
{
    for (const size of [2048, 6144, 12288, 18432]) {
        const out = go(['overhead', String(size), String(fstream.QR_BLOCK_SIZE), '60']).trim().split(' ');
        const k = +out[0];
        const worst = +out[1];
        const median = +out[2];
        const budget = fstream.framesPerPass(k);
        const typical = fstream.framesTypical(k);
        assert(
            worst <= budget,
            `${size} B pack (k=${k}): worst of 60 decodes took ${worst} frames, pass budget ${budget}`,
        );
        assert(
            median <= typical && typical < budget,
            `${size} B pack (k=${k}): median decode ${median} <= "usually done" mark ${typical} < pass ${budget}`,
        );
    }
}

// =====================================================================
section('6. A pack far bigger than any .sbp still fits the screen');
{
    // 512 KB is ~30x a real pack. The buffer must stay bounded, the
    // display must never starve, and the counters must stay honest.
    const size = 512 * 1024;
    const k = Math.ceil(size / fstream.QR_BLOCK_SIZE);
    const stream = new fstream.FrameStream();
    const perPass = fstream.framesPerPass(k);
    assert(perPass === 3 * k + 96, `framesPerPass(${k}) = ${perPass}`);

    // Feed 50k frames while pulling 1 per 4 pushed: the producer wins,
    // which is exactly what the Rust event stream does.
    let pulled = 0;
    for (let i = 0; i < 50000; i++) {
        stream.push({ i, k, frame_b64: 'x'.repeat(fstream.QR_FRAME_CHARS) });
        if (i % 4 === 0) {
            if (stream.next() === null) {
                bad('big pack: display starved', `at push ${i}`);
                break;
            }
            pulled++;
        }
    }
    assert(pulled === 12500, `pulled ${pulled} frames while 50000 arrived`);
    assert(stream.pending + pulled <= fstream.MAX_BUFFERED + 50000, 'buffer accounting is sane');
    const retained = stream.pending;
    assert(retained <= fstream.MAX_BUFFERED, `retained ${retained} unseen frames, cap ${fstream.MAX_BUFFERED}`);
    assert(stream.shown === pulled, 'shown counter matches pulls');
    assert(stream.pass === Math.floor((pulled - 1) / perPass) + 1, 'pass counter tracks a long stream');

    // Starvation: a stalled producer must replay, not freeze.
    const starved = new fstream.FrameStream();
    for (let i = 0; i < 10; i++) starved.push({ i, k: 5, frame_b64: `f${i}` });
    const seq = [];
    for (let i = 0; i < 40; i++) seq.push(starved.next());
    assert(seq.every((s) => s !== null), 'a stalled producer replays instead of freezing');
    assert(new Set(seq).size === 10, 'replay cycles the frames it has');
    assert(starved.pass === Math.floor(39 / fstream.framesPerPass(5)) + 1, 'pass counter still advances while replaying');
}

console.log(`\n[check-qr-send] ${checks - failures}/${checks} checks passed.`);
if (failures > 0) {
    console.error(`[check-qr-send] FAILED: ${failures} check(s).`);
    process.exit(1);
}
