// RecipientImport.tsx — the QR-fountain receive lane.
//
// Three ways in, one decoder behind all of them:
//   * camera — getUserMedia + jsQR, decoding frames off a canvas;
//   * paste  — base64url frames (or `daal-deploy qr-fountain` JSON
//              lines) typed or pasted into a box, no permission needed;
//   * file   — the same text dropped in as a file.
//
// All three normalise through `frames.ts` and feed
// `recipient_qr_feed_frame`. Completion is decided by ONE predicate,
// `isComplete()` in sessionStatus.ts, against a status that has been
// validated against the Rust contract.
//
// WHAT THIS SCREEN PROMISES THE USER
//
// 1. Progress is the DECODER's progress. "Blocks recovered" comes from
//    the fountain decoder; "frames read" counts what the camera saw.
//    When the camera is reading but blocks are not rising, the user can
//    see that directly instead of watching a spinner lie to them.
// 2. Pausing costs nothing. The Go decoder holds its recovered blocks
//    against the session id, so stopping the camera and resuming later
//    keeps every block. Only Discard (or closing the sheet) throws the
//    session away, and Discard asks first.
// 3. A scan that cannot finish says what is missing — how many blocks,
//    and why it might be stalling — rather than failing blank.

import { useCallback, useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';
import { Recipient } from './recipientCommands';
import {
    blocksRemaining,
    decodeProgress,
    isComplete,
    SessionContractError,
    type SessionStatus,
} from './sessionStatus';
import { normalizeFrameText, parseFrameLines } from './frames';
import { friendlyError } from '../lib/importVerdict';
import { Button } from '../design/primitives';

type Mode = 'camera' | 'paste' | 'file';

/**
 * Camera lifecycle. The three refusal states are deliberately
 * distinct because the user's next action differs for each:
 *   denied  — the OS may ask again, so offer to ask again;
 *   blocked — it will not ask again, so give the Settings path;
 *   none / busy / unavailable — the camera is not the way in at all,
 *   so point at Paste.
 */
type CamState =
    | 'idle'
    | 'requesting'
    | 'live'
    | 'paused'
    | 'denied'
    | 'blocked'
    | 'none'
    | 'busy'
    | 'unavailable';

/** No decoder progress for this long while the camera runs => stalled. */
const STALL_MS = 6000;
/** Camera sampling period. ~8/s is plenty for an animated QR. */
const TICK_MS = 120;

interface Props {
    t: (k: string) => string;
    onVerdict: (verdict: string) => void;
    onClose: () => void;
}

export default function RecipientImport({ t, onVerdict, onClose }: Props) {
    const [mode, setMode] = useState<Mode>('camera');
    const [status, setStatus] = useState<SessionStatus | null>(null);
    const [error, setError] = useState<string | null>(null);
    /** Set when the shell/UI contract itself is broken — a build bug,
     *  not a user problem, and it gets its own copy. */
    const [contractBroken, setContractBroken] = useState(false);
    const [framesRead, setFramesRead] = useState(0);
    const [stalled, setStalled] = useState(false);
    const [confirmDiscard, setConfirmDiscard] = useState(false);
    const [notice, setNotice] = useState<string | null>(null);
    /** True when a whole pasted/dropped batch was consumed and the
     *  decode still is not finished — the "we ran out of frames" case,
     *  which must say what is missing instead of just sitting there. */
    const [batchIncomplete, setBatchIncomplete] = useState(false);

    // The session id lives in a ref as well as state: the camera loop
    // is a closure that must not be torn down and rebuilt (and thus
    // restart the scan) every time a status update re-renders.
    const sessionRef = useRef<string | null>(null);
    const [sessionId, setSessionId] = useState<string | null>(null);
    const lastProgressAt = useRef<number>(Date.now());
    const lastReceived = useRef<number>(-1);
    const doneRef = useRef(false);

    const ensureSession = useCallback(async (): Promise<string> => {
        if (sessionRef.current) return sessionRef.current;
        const id = await Recipient.newSession();
        sessionRef.current = id;
        setSessionId(id);
        return id;
    }, []);

    /** Feed one normalised frame and absorb the new status. Returns
     *  true once the decode is complete. */
    const feed = useCallback(
        async (frameB64: string): Promise<boolean> => {
            if (doneRef.current) return true;
            const id = await ensureSession();
            const s = await Recipient.feedFrame(id, 0, 0, frameB64);
            setStatus(s);
            setFramesRead((n) => n + 1);
            if (s.received !== lastReceived.current) {
                lastReceived.current = s.received;
                lastProgressAt.current = Date.now();
                setStalled(false);
            }
            if (isComplete(s)) {
                doneRef.current = true;
                const verdict = await Recipient.finalize(id);
                // The session is consumed by a successful finalize.
                sessionRef.current = null;
                onVerdict(verdict);
                return true;
            }
            return false;
        },
        [ensureSession, onVerdict],
    );

    /** Feed a whole batch (paste / file). Reports the "ran out of
     *  frames" outcome rather than leaving the user with a stalled bar
     *  and no explanation. */
    const feedBatch = useCallback(
        async (frames: string[]): Promise<void> => {
            setBatchIncomplete(false);
            for (const f of frames) {
                if (await feed(f)) return;
            }
            if (!doneRef.current) setBatchIncomplete(true);
        },
        [feed],
    );

    /** Route every failure to the right piece of copy. A contract
     *  mismatch is a build bug and must not masquerade as a scan
     *  problem. */
    const report = useCallback(
        (e: unknown) => {
            if (e instanceof SessionContractError) {
                setContractBroken(true);
                // Keep the technical detail for a bug report.
                setError(e.message);
                return;
            }
            // Route through the same mapper the file and paste lanes
            // use. Painting e.message verbatim is how Go's
            // `illegal base64 data at input byte 7` ends up shown in
            // English, in a Latin string, inside a Farsi RTL panel,
            // with no next action attached.
            setError(friendlyError(t, e instanceof Error ? e.message : String(e)));
        },
        [t],
    );

    // Discard-on-close. Pausing must NOT come through here, which is
    // why the camera loop is torn down independently of the session.
    useEffect(() => {
        return () => {
            const id = sessionRef.current;
            if (id && !doneRef.current) Recipient.cancel(id).catch(() => {});
        };
    }, []);

    // Stall detection: the decoder, not the camera, defines progress.
    const [camState, setCamState] = useState<CamState>('idle');
    useEffect(() => {
        if (camState !== 'live' || doneRef.current) {
            setStalled(false);
            return;
        }
        const h = window.setInterval(() => {
            if (Date.now() - lastProgressAt.current > STALL_MS) setStalled(true);
        }, 1000);
        return () => window.clearInterval(h);
    }, [camState]);

    const remaining = blocksRemaining(status);
    const progress = decodeProgress(status);

    const discard = async () => {
        const id = sessionRef.current;
        sessionRef.current = null;
        setSessionId(null);
        setStatus(null);
        setFramesRead(0);
        setStalled(false);
        setBatchIncomplete(false);
        setConfirmDiscard(false);
        lastReceived.current = -1;
        if (id) await Recipient.cancel(id).catch(() => {});
    };

    return (
        <div>
            <p style={{ color: 'var(--paper-dim)', fontSize: 13, margin: '0 0 14px' }}>
                {t('scan.lede')}
            </p>

            <div role="tablist" style={tabRow()}>
                {(['camera', 'paste', 'file'] as Mode[]).map((m) => (
                    <button
                        key={m}
                        role="tab"
                        aria-selected={mode === m}
                        onClick={() => setMode(m)}
                        style={tabBtn(mode === m)}
                    >
                        {t(`scan.mode.${m}`)}
                    </button>
                ))}
            </div>

            {contractBroken ? (
                <Panel tone="danger" title={t('scan.contract.title')}>
                    <div>{t('scan.contract.body')}</div>
                    {error && <Mono>{error}</Mono>}
                </Panel>
            ) : (
                <>
                    {mode === 'camera' && (
                        <CameraLane
                            t={t}
                            camState={camState}
                            setCamState={setCamState}
                            onFrame={feed}
                            onError={report}
                            onFallback={() => setMode('paste')}
                        />
                    )}

                    {mode === 'paste' && (
                        <PasteLane
                            t={t}
                            onFeedBatch={feedBatch}
                            onError={report}
                            onNotice={setNotice}
                        />
                    )}

                    {mode === 'file' && (
                        <FileLane
                            t={t}
                            onFeedBatch={feedBatch}
                            onError={report}
                            onNotice={setNotice}
                        />
                    )}

                    <ProgressPanel
                        t={t}
                        status={status}
                        progress={progress}
                        framesRead={framesRead}
                        paused={camState === 'paused'}
                    />

                    {stalled && !doneRef.current && (
                        <Panel tone="warn" title={t('scan.stall.title')}>
                            {remaining == null || remaining === 0
                                ? t('scan.stall.nothing')
                                : t('scan.stall.body').replace('{n}', String(remaining))}
                        </Panel>
                    )}

                    {batchIncomplete && !doneRef.current && (
                        <Panel tone="warn" title={t('scan.incomplete.title')}>
                            {t('scan.incomplete.body')
                                .replace('{n}', String(remaining ?? status?.total_frames ?? 0))
                                .replace('{total}', String(status?.total_frames ?? 0))}
                        </Panel>
                    )}

                    {notice && <Panel tone="warn">{notice}</Panel>}

                    {error && !contractBroken && (
                        <Panel tone="danger" title={t('scan.err.title')}>
                            {error}
                        </Panel>
                    )}
                </>
            )}

            <div style={{ display: 'flex', gap: 8, marginTop: 16, flexWrap: 'wrap' }}>
                {sessionId && !confirmDiscard && (
                    <Button variant="ghost" onClick={() => setConfirmDiscard(true)}>
                        {t('scan.discard')}
                    </Button>
                )}
                {confirmDiscard && (
                    <>
                        <span style={{ fontSize: 13, color: 'var(--paper-dim)', alignSelf: 'center' }}>
                            {t('scan.discard.confirm')}
                        </span>
                        <Button variant="ghost" onClick={() => setConfirmDiscard(false)}>
                            {t('common.cancel')}
                        </Button>
                        <Button onClick={() => void discard()}>{t('scan.discard')}</Button>
                    </>
                )}
                <div style={{ flex: 1 }} />
                <Button variant="ghost" onClick={onClose}>
                    {t('common.cancel')}
                </Button>
            </div>

            {sessionId && (
                <Mono>session {sessionId.slice(0, 16)}…</Mono>
            )}
        </div>
    );
}

// ---- Progress ----------------------------------------------------

function ProgressPanel({
    t,
    status,
    progress,
    framesRead,
    paused,
}: {
    t: (k: string) => string;
    status: SessionStatus | null;
    progress: number | null;
    framesRead: number;
    paused: boolean;
}) {
    const done = status?.received ?? 0;
    const total = status?.total_frames ?? 0;
    return (
        <div style={{ marginTop: 14 }}>
            <div
                style={{
                    height: 6,
                    borderRadius: 3,
                    background: 'var(--teal-deep)',
                    overflow: 'hidden',
                }}
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={total || undefined}
                aria-valuenow={total ? done : undefined}
            >
                <div
                    style={{
                        width: `${Math.round((progress ?? 0) * 100)}%`,
                        height: '100%',
                        background: 'var(--gold)',
                        transition: 'width 160ms linear',
                    }}
                />
            </div>
            {/* NO font-mono here. These are whole translated sentences
                ("{done} از {total} بخش بازیابی شد"), not machine text.
                An inline fontFamily beats the :root[dir="rtl"] rule that
                supplies --font-fa, and --font-mono has no Persian
                coverage, so Farsi fell back to a generic unshaped face —
                on the one readout a sender holding the phone steady is
                actually watching. */}
            <div
                style={{
                    marginTop: 8,
                    fontSize: 12,
                    color: 'var(--paper-dim)',
                    fontVariantNumeric: 'tabular-nums',
                    display: 'flex',
                    gap: 14,
                    flexWrap: 'wrap',
                }}
            >
                <span>
                    {total === 0
                        ? t('scan.progress.waiting')
                        : t('scan.progress.blocks')
                              .replace('{done}', String(done))
                              .replace('{total}', String(total))}
                </span>
                <span>{t('scan.progress.seen').replace('{n}', String(framesRead))}</span>
                {status && status.bytes_decoded > 0 && (
                    <span>
                        {t('scan.progress.bytes').replace('{n}', String(status.bytes_decoded))}
                    </span>
                )}
            </div>
            {paused && (
                <div style={{ marginTop: 6, fontSize: 12, color: 'var(--paper-dim)' }}>
                    {t('scan.progress.paused')}
                </div>
            )}
            {status && isComplete(status) && (
                <div style={{ marginTop: 6, fontSize: 12, color: 'var(--gold)' }}>
                    {t('scan.progress.complete')}
                </div>
            )}
        </div>
    );
}

// ---- Camera ------------------------------------------------------

function classifyCameraError(e: unknown, alreadyRefusedOnce: boolean): CamState {
    const name = (e as { name?: string })?.name ?? '';
    switch (name) {
        case 'NotAllowedError':
        case 'PermissionDeniedError':
        case 'SecurityError':
            // A refusal that survives an explicit second ask is a
            // remembered "never ask again", and the user has to go to
            // Settings. Asking again would just fail silently.
            return alreadyRefusedOnce ? 'blocked' : 'denied';
        case 'NotFoundError':
        case 'DevicesNotFoundError':
        case 'OverconstrainedError':
            return 'none';
        case 'NotReadableError':
        case 'TrackStartError':
            return 'busy';
        default:
            return 'unavailable';
    }
}

function CameraLane({
    t,
    camState,
    setCamState,
    onFrame,
    onError,
    onFallback,
}: {
    t: (k: string) => string;
    camState: CamState;
    setCamState: (s: CamState) => void;
    onFrame: (frameB64: string) => Promise<boolean>;
    onError: (e: unknown) => void;
    onFallback: () => void;
}) {
    const videoRef = useRef<HTMLVideoElement | null>(null);
    const canvasRef = useRef<HTMLCanvasElement | null>(null);
    const streamRef = useRef<MediaStream | null>(null);
    const refusals = useRef(0);
    /** Frames already fed. An animated QR sits on screen for several
     *  camera ticks; re-feeding the identical frame is pure IPC waste. */
    const seen = useRef<Set<string>>(new Set());

    const stopStream = useCallback(() => {
        streamRef.current?.getTracks().forEach((tr) => tr.stop());
        streamRef.current = null;
        if (videoRef.current) videoRef.current.srcObject = null;
    }, []);

    const start = useCallback(async () => {
        if (
            typeof navigator === 'undefined' ||
            !navigator.mediaDevices?.getUserMedia
        ) {
            setCamState('unavailable');
            return;
        }
        setCamState('requesting');

        // If the platform can tell us the permission is already a hard
        // "denied", say so up front instead of making the user press a
        // button that cannot work.
        try {
            const perms = (navigator as Navigator & {
                permissions?: {
                    query: (d: { name: string }) => Promise<{ state: string }>;
                };
            }).permissions;
            if (perms?.query) {
                const st = await perms.query({ name: 'camera' });
                if (st.state === 'denied') {
                    setCamState('blocked');
                    return;
                }
            }
        } catch {
            // Permissions API absent or does not know "camera"; fall
            // through and just ask.
        }

        try {
            const stream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: 'environment' },
                audio: false,
            });
            streamRef.current = stream;
            if (videoRef.current) {
                videoRef.current.srcObject = stream;
                await videoRef.current.play();
            }
            setCamState('live');
        } catch (e) {
            const next = classifyCameraError(e, refusals.current > 0);
            if (next === 'denied' || next === 'blocked') refusals.current += 1;
            setCamState(next);
        }
    }, [setCamState]);

    // Release the camera whenever we are not actively scanning.
    useEffect(() => {
        if (camState !== 'live') stopStream();
    }, [camState, stopStream]);
    useEffect(() => stopStream, [stopStream]);

    // The decode loop.
    useEffect(() => {
        if (camState !== 'live') return;
        let cancelled = false;

        const tick = async () => {
            const v = videoRef.current;
            const c = canvasRef.current;
            if (!v || !c || v.videoWidth === 0) return;
            c.width = v.videoWidth;
            c.height = v.videoHeight;
            const ctx = c.getContext('2d', { willReadFrequently: true });
            if (!ctx) return;
            ctx.drawImage(v, 0, 0, c.width, c.height);
            const img = ctx.getImageData(0, 0, c.width, c.height);
            const code = jsQR(img.data, img.width, img.height, {
                inversionAttempts: 'dontInvert',
            });
            if (!code?.data) return;

            let frame: string;
            try {
                // The QR already carries the base64url frame text.
                // Forward it VERBATIM — see frames.ts on the btoa bug.
                frame = normalizeFrameText(code.data);
            } catch {
                // A QR that is not one of our frames (someone else's
                // code in shot). Ignore it rather than erroring.
                return;
            }
            if (seen.current.has(frame)) return;
            seen.current.add(frame);
            if (await onFrame(frame)) cancelled = true;
        };

        let timer = 0;
        const loop = async () => {
            while (!cancelled) {
                try {
                    await tick();
                } catch (e) {
                    onError(e);
                    return;
                }
                await new Promise<void>((r) => {
                    timer = window.setTimeout(r, TICK_MS);
                });
            }
        };
        void loop();

        return () => {
            cancelled = true;
            window.clearTimeout(timer);
        };
    }, [camState, onFrame, onError]);

    const refusal: Partial<Record<CamState, { key: string; retry: boolean }>> = {
        denied: { key: 'denied', retry: true },
        blocked: { key: 'blocked', retry: false },
        none: { key: 'none', retry: false },
        busy: { key: 'busy', retry: true },
        unavailable: { key: 'unavailable', retry: false },
    };
    const r = refusal[camState];

    return (
        <div>
            <div
                style={{
                    position: 'relative',
                    borderRadius: 10,
                    overflow: 'hidden',
                    background: 'var(--teal-deep)',
                    aspectRatio: '4 / 3',
                    display: camState === 'live' || camState === 'paused' ? 'block' : 'none',
                }}
            >
                <video
                    ref={videoRef}
                    playsInline
                    muted
                    style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                />
            </div>
            <canvas ref={canvasRef} style={{ display: 'none' }} />

            {camState === 'requesting' && (
                <Panel>{t('scan.cam.requesting')}</Panel>
            )}

            {r && (
                <Panel tone="warn" title={t(`scan.cam.${r.key}.title`)}>
                    <div>{t(`scan.cam.${r.key}.body`)}</div>
                    <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
                        {r.retry && (
                            <Button onClick={() => void start()}>
                                {t('scan.cam.denied.retry')}
                            </Button>
                        )}
                        <Button variant="ghost" onClick={onFallback}>
                            {t('scan.cam.use_paste')}
                        </Button>
                    </div>
                </Panel>
            )}

            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                {(camState === 'idle' || camState === 'paused') && (
                    <Button onClick={() => void start()}>
                        {camState === 'paused' ? t('scan.resume') : t('scan.start')}
                    </Button>
                )}
                {camState === 'live' && (
                    <Button variant="ghost" onClick={() => setCamState('paused')}>
                        {t('scan.pause')}
                    </Button>
                )}
            </div>
        </div>
    );
}

// ---- Paste -------------------------------------------------------

function PasteLane({
    t,
    onFeedBatch,
    onError,
    onNotice,
}: {
    t: (k: string) => string;
    onFeedBatch: (frames: string[]) => Promise<void>;
    onError: (e: unknown) => void;
    onNotice: (s: string | null) => void;
}) {
    const [text, setText] = useState('');
    const [busy, setBusy] = useState(false);
    return (
        <div>
            <p style={{ fontSize: 12, color: 'var(--paper-dim)', margin: '10px 0 6px' }}>
                {t('scan.paste.label')}
            </p>
            <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={8}
                placeholder={t('scan.paste.placeholder')}
                style={textareaStyle()}
            />
            <Button
                disabled={busy || !text.trim()}
                onClick={async () => {
                    setBusy(true);
                    onNotice(null);
                    try {
                        const { frames, rejected } = parseFrameLines(text);
                        if (frames.length === 0) {
                            onNotice(t('scan.paste.none'));
                            return;
                        }
                        if (rejected.length > 0) {
                            onNotice(
                                t('scan.paste.rejected').replace(
                                    '{n}',
                                    String(rejected.length),
                                ),
                            );
                        }
                        await onFeedBatch(frames);
                    } catch (e) {
                        onError(e);
                    } finally {
                        setBusy(false);
                    }
                }}
            >
                {t('scan.paste.feed')}
            </Button>
        </div>
    );
}

// ---- File --------------------------------------------------------

function FileLane({
    t,
    onFeedBatch,
    onError,
    onNotice,
}: {
    t: (k: string) => string;
    onFeedBatch: (frames: string[]) => Promise<void>;
    onError: (e: unknown) => void;
    onNotice: (s: string | null) => void;
}) {
    return (
        <div style={{ marginTop: 12 }}>
            <label style={{ fontSize: 13, color: 'var(--paper-dim)' }}>
                {t('scan.file.choose')}
                <input
                    type="file"
                    accept=".txt,.jsonl,text/plain"
                    style={{ display: 'block', marginTop: 8 }}
                    onChange={async (e) => {
                        const f = e.target.files?.[0];
                        if (!f) return;
                        onNotice(null);
                        try {
                            const { frames, rejected } = parseFrameLines(await f.text());
                            if (frames.length === 0) {
                                onNotice(t('scan.paste.none'));
                                return;
                            }
                            if (rejected.length > 0) {
                                onNotice(
                                    t('scan.paste.rejected').replace(
                                        '{n}',
                                        String(rejected.length),
                                    ),
                                );
                            }
                            await onFeedBatch(frames);
                        } catch (err) {
                            onError(err);
                        }
                    }}
                />
            </label>
        </div>
    );
}

// ---- Bits --------------------------------------------------------

function Panel({
    tone = 'info',
    title,
    children,
}: {
    tone?: 'info' | 'warn' | 'danger';
    title?: string;
    children: React.ReactNode;
}) {
    const palette = {
        info: ['rgba(122,162,159,0.10)', 'rgba(122,162,159,0.35)', 'var(--paper-dim)'],
        warn: ['rgba(193,158,80,0.10)', 'rgba(193,158,80,0.40)', 'var(--gold-warm)'],
        danger: ['rgba(200,85,61,0.10)', 'rgba(200,85,61,0.40)', 'var(--danger)'],
    }[tone];
    return (
        <div
            style={{
                background: palette[0],
                border: `1px solid ${palette[1]}`,
                color: palette[2],
                padding: 12,
                borderRadius: 'var(--radius-md)',
                margin: '12px 0',
                fontSize: 13,
                lineHeight: 1.5,
            }}
        >
            {title && <div style={{ fontWeight: 600, marginBottom: 4 }}>{title}</div>}
            {children}
        </div>
    );
}

function Mono({ children }: { children: React.ReactNode }) {
    return (
        <div
            style={{
                marginTop: 8,
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                color: 'var(--dim)',
                wordBreak: 'break-all',
            }}
        >
            {children}
        </div>
    );
}

function tabRow() {
    return {
        display: 'flex',
        gap: 4,
        background: 'var(--teal-deep)',
        padding: 4,
        borderRadius: 'var(--radius-md)',
        marginBottom: 12,
    } as const;
}

function tabBtn(active: boolean) {
    return {
        flex: 1,
        background: active ? 'var(--teal-raised)' : 'transparent',
        border: 0,
        color: active ? 'var(--paper)' : 'var(--paper-dim)',
        padding: '8px 10px',
        borderRadius: 'var(--radius-md)',
        cursor: 'pointer',
        fontFamily: 'var(--font-body)',
        fontSize: 13,
    } as const;
}

function textareaStyle() {
    return {
        width: '100%',
        background: 'var(--teal-deep)',
        color: 'var(--paper)',
        border: '1px solid var(--teal-border)',
        padding: 8,
        borderRadius: 'var(--radius-md)',
        fontFamily: 'var(--font-mono)',
        fontSize: 12,
    } as const;
}
