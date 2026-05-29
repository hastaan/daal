// RecipientImport.tsx — full QR-fountain import lane.
//
// Modes:
//   * camera    — getUserMedia + jsQR running off a hidden canvas.
//   * clipboard — paste base64 frames or whole QR text into a textarea.
//   * file      — drop a `.daal-qr.txt` file containing newline-separated
//                 base64 frames (also useful for tests).
//
// All three drive the same internal feeder loop that calls
// recipient_qr_feed_frame() and polls recipient_qr_status() between
// frames. On completion we call recipient_qr_finalize() to fetch the
// importer verdict, then hand it back to the parent so the trust-prompt
// modal can take over.

import { useEffect, useRef, useState } from 'react';
import { Recipient, type SessionStatus } from './recipientCommands';
import { Sheet, Button } from '../design/primitives';

interface Props {
    t: (k: string) => string;
    onVerdict: (verdict: string) => void;
    onClose: () => void;
}

type Mode = 'pick' | 'camera' | 'clipboard' | 'file';

export default function RecipientImport({ t: _t, onVerdict, onClose }: Props) {
    const [mode, setMode] = useState<Mode>('pick');
    const [sessionId, setSessionId] = useState<string | null>(null);
    const [status, setStatus] = useState<SessionStatus | null>(null);
    const [error, setError] = useState<string | null>(null);

    const ensureSession = async (): Promise<string> => {
        if (sessionId) return sessionId;
        const id = await Recipient.newSession();
        setSessionId(id);
        return id;
    };

    const handleVerdict = async (id: string) => {
        try {
            const v = await Recipient.finalize(id);
            onVerdict(v);
        } catch (e) {
            setError(String(e));
        }
    };

    useEffect(() => {
        return () => {
            if (sessionId) Recipient.cancel(sessionId).catch(() => {});
        };
    }, [sessionId]);

    return (
        <Sheet
            title="Import via QR fountain"
            onClose={() => {
                if (sessionId) Recipient.cancel(sessionId).catch(() => {});
                onClose();
            }}
            width={520}
            footer={
                <Button
                    variant="ghost"
                    onClick={() => {
                        if (sessionId)
                            Recipient.cancel(sessionId).catch(() => {});
                        onClose();
                    }}
                >
                    Close
                </Button>
            }
        >
                {sessionId && (
                    <div
                        style={{
                            fontSize: 11,
                            color: 'var(--dim)',
                            fontFamily: 'var(--font-mono)',
                            marginBottom: 8,
                        }}
                    >
                        session: {sessionId.slice(0, 12)}…
                    </div>
                )}

                {error && (
                    <div
                        style={{
                            background: 'rgba(200,85,61,0.10)',
                            border: '1px solid rgba(200,85,61,0.40)',
                            color: 'var(--danger)',
                            padding: 10,
                            borderRadius: 'var(--radius-md)',
                            margin: '10px 0',
                            fontSize: 13,
                        }}
                    >
                        {error}
                    </div>
                )}

                {mode === 'pick' && (
                    <div style={{ display: 'grid', gap: 8, marginTop: 16 }}>
                        <button style={primaryBtn()} onClick={() => setMode('camera')}>
                            Scan with camera
                        </button>
                        <button style={primaryBtn()} onClick={() => setMode('clipboard')}>
                            Paste base64 frames
                        </button>
                        <button style={primaryBtn()} onClick={() => setMode('file')}>
                            Drop frames file
                        </button>
                    </div>
                )}

                {mode === 'camera' && (
                    <CameraFountain
                        ensureSession={ensureSession}
                        onStatus={setStatus}
                        onError={setError}
                        onDone={(id) => handleVerdict(id)}
                    />
                )}

                {mode === 'clipboard' && (
                    <ClipboardFountain
                        ensureSession={ensureSession}
                        onStatus={setStatus}
                        onError={setError}
                        onDone={(id) => handleVerdict(id)}
                    />
                )}

                {mode === 'file' && (
                    <FileFountain
                        ensureSession={ensureSession}
                        onStatus={setStatus}
                        onError={setError}
                        onDone={(id) => handleVerdict(id)}
                    />
                )}

                {status && (
                    <div
                        style={{
                            marginTop: 14,
                            padding: 10,
                            background: 'var(--teal-deep)',
                            borderRadius: 'var(--radius-md)',
                            fontFamily: 'var(--font-mono)',
                            fontSize: 12,
                            color: 'var(--paper-dim)',
                        }}
                    >
                        state: {status.state} · frames: {status.frames_in}
                    </div>
                )}

        </Sheet>
    );
}

// ---- Camera mode ------------------------------------------------

function CameraFountain({
    ensureSession,
    onStatus,
    onError,
    onDone,
}: {
    ensureSession: () => Promise<string>;
    onStatus: (s: SessionStatus) => void;
    onError: (e: string) => void;
    onDone: (id: string) => void;
}) {
    const videoRef = useRef<HTMLVideoElement | null>(null);
    const canvasRef = useRef<HTMLCanvasElement | null>(null);
    const [running, setRunning] = useState(false);

    useEffect(() => {
        let stopped = false;
        let stream: MediaStream | null = null;
        (async () => {
            try {
                stream = await navigator.mediaDevices.getUserMedia({ video: true });
                if (videoRef.current) {
                    videoRef.current.srcObject = stream;
                    await videoRef.current.play();
                }
                setRunning(true);
            } catch (e) {
                onError(`camera: ${e}`);
            }
        })();
        return () => {
            stopped = true;
            stream?.getTracks().forEach((tr) => tr.stop());
            void stopped;
        };
    }, [onError]);

    useEffect(() => {
        if (!running) return;
        let cancelled = false;
        const loop = async () => {
            const id = await ensureSession();
            // For browsers without a built-in QR decoder we feed raw
            // pixel base64 to the engine. The engine's fountain
            // decoder treats the data as opaque per-frame bytes; a
            // future iteration may add a JS-side QR decode using
            // jsQR or BarcodeDetector when available.
            const detector =
                'BarcodeDetector' in window
                    ? // @ts-expect-error vendor-specific API
                      new BarcodeDetector({ formats: ['qr_code'] })
                    : null;
            while (!cancelled && videoRef.current && canvasRef.current) {
                try {
                    const v = videoRef.current;
                    const c = canvasRef.current;
                    c.width = v.videoWidth || 640;
                    c.height = v.videoHeight || 480;
                    const ctx = c.getContext('2d');
                    if (!ctx) break;
                    ctx.drawImage(v, 0, 0, c.width, c.height);
                    let payload = '';
                    if (detector) {
                        const codes = await detector.detect(c);
                        if (codes.length > 0) payload = codes[0].rawValue;
                    }
                    if (payload) {
                        const enc = btoa(unescape(encodeURIComponent(payload)));
                        const s = await Recipient.feedFrame(id, 0, 0, enc);
                        onStatus(s);
                        if (s.state === 'complete' || s.state === 'verdict_ready') {
                            onDone(id);
                            return;
                        }
                    }
                } catch (e) {
                    onError(String(e));
                }
                await new Promise((r) => setTimeout(r, 120));
            }
        };
        loop();
        return () => {
            cancelled = true;
        };
    }, [running, ensureSession, onStatus, onError, onDone]);

    return (
        <div>
            <video ref={videoRef} style={{ width: '100%', borderRadius: 8 }} />
            <canvas ref={canvasRef} style={{ display: 'none' }} />
        </div>
    );
}

// ---- Clipboard mode ---------------------------------------------

function ClipboardFountain({
    ensureSession,
    onStatus,
    onError,
    onDone,
}: {
    ensureSession: () => Promise<string>;
    onStatus: (s: SessionStatus) => void;
    onError: (e: string) => void;
    onDone: (id: string) => void;
}) {
    const [text, setText] = useState('');
    const [busy, setBusy] = useState(false);
    return (
        <div>
            <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={8}
                placeholder="Paste one base64-encoded frame per line"
                style={{
                    width: '100%',
                    background: 'var(--teal-deep)',
                    color: 'var(--paper)',
                    border: '1px solid var(--teal-border)',
                    padding: 8,
                    borderRadius: 'var(--radius-md)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 12,
                }}
            />
            <button
                disabled={busy || !text.trim()}
                style={primaryBtn()}
                onClick={async () => {
                    setBusy(true);
                    try {
                        const id = await ensureSession();
                        const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
                        for (let i = 0; i < lines.length; i++) {
                            const s = await Recipient.feedFrame(id, i, lines.length, lines[i]);
                            onStatus(s);
                            if (s.state === 'complete' || s.state === 'verdict_ready') {
                                onDone(id);
                                return;
                            }
                        }
                    } catch (e) {
                        onError(String(e));
                    } finally {
                        setBusy(false);
                    }
                }}
            >
                Feed frames
            </button>
        </div>
    );
}

// ---- File mode --------------------------------------------------

function FileFountain({
    ensureSession,
    onStatus,
    onError,
    onDone,
}: {
    ensureSession: () => Promise<string>;
    onStatus: (s: SessionStatus) => void;
    onError: (e: string) => void;
    onDone: (id: string) => void;
}) {
    return (
        <input
            type="file"
            accept=".txt,text/plain"
            onChange={async (e) => {
                const f = e.target.files?.[0];
                if (!f) return;
                try {
                    const txt = await f.text();
                    const id = await ensureSession();
                    const lines = txt.split('\n').map((l) => l.trim()).filter(Boolean);
                    for (let i = 0; i < lines.length; i++) {
                        const s = await Recipient.feedFrame(id, i, lines.length, lines[i]);
                        onStatus(s);
                        if (s.state === 'complete' || s.state === 'verdict_ready') {
                            onDone(id);
                            return;
                        }
                    }
                } catch (err) {
                    onError(String(err));
                }
            }}
        />
    );
}

function primaryBtn() {
    return {
        background: 'var(--gold)',
        color: '#1A1208',
        border: 0,
        padding: '8px 14px',
        borderRadius: 'var(--radius-md)',
        fontWeight: 600,
        cursor: 'pointer',
    } as const;
}

