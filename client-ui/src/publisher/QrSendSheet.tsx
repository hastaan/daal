// QrSendSheet — hand a relay's pack to another phone with light.
//
// This is the offline path that survives the channel the adversary
// actually controls. Every other way of moving a `.sbp` puts a file on
// a network someone else runs: a 5 MB messenger cap, a ban on
// executables, server-side scanning, entropy and packet-size alarms. A
// QR code on a screen is not on that network at all. It is the one
// transport that keeps working during a blackout, and the only thing it
// costs is two people standing next to each other.
//
// WHAT IT SENDS
//
// The everyone pack (`<id>.shared.sbp`) — the file that can actually
// connect somebody. Not the raw signed bundle, which relay detail
// itself labels "not connectable"; see `wcmd::qr_render`, which now
// refuses to guess between the two.
//
// HOW IT MOVES
//
// `daal-deploy qr-fountain` turns the pack into an endless stream of
// LT-fountain frames. Any sufficiently large SUBSET of frames
// reconstructs the file, so the receiver never has to catch a specific
// frame and neither phone needs a back-channel to say "missed one,
// resend". That is what makes a one-way screen enough.
//
// The numbers — 96-byte blocks, ECC Q, 5 fps, one pass = 3k+96 frames —
// and the reasoning for each are in `../qr/fountainStream.ts`, next to
// the constants themselves. The QR encoder is `../qr/qrcodegen.ts`,
// vendored source with no dependencies, because an encoder fetched at
// runtime is an encoder that fails exactly when this screen matters.
//
// WHAT IT CANNOT KNOW
//
// Whether it worked. There is no back-channel off a screen — that is
// the point — so this screen never claims success. It reports what it
// has actually done (frames shown, passes completed) and says plainly
// that the other phone is the only thing that knows when to stop.

import { useCallback, useEffect, useRef, useState } from 'react';
import type { UnlistenFn } from '@tauri-apps/api/event';
import { Wizard, onQrFrame } from './wizardCommands';
import { Button, Card, Sheet, Segmented } from '../design/primitives';
import { modulePxFor, paintFrame, paintedModules } from '../qr/paint';
import {
    BATCH_FRAMES,
    FPS_SLOW,
    FPS_STEADY,
    FrameStream,
    QR_BLOCK_SIZE,
    framesPerPass,
    framesTypical,
} from '../qr/fountainStream';

interface Props {
    t: (k: string) => string;
    operatorId: number;
    /** What the user calls this relay, for the "what am I sending" line. */
    relayName: string;
    onClose: () => void;
}

/** Longest side of the symbol on screen, in CSS pixels, before it is
 *  snapped down to a whole number of device pixels per module. */
const TARGET_CSS_PX = 340;

type Speed = 'steady' | 'slow';

export function QrSendSheet({ t, operatorId, relayName, onClose }: Props) {
    const canvasRef = useRef<HTMLCanvasElement | null>(null);
    const streamRef = useRef(new FrameStream());
    const inFlightRef = useRef(false);
    const exhaustedRef = useRef(false);
    /** Set when a frame could not be encoded at all. Nothing useful can
     *  follow it, and re-throwing 5 times a second helps nobody. */
    const encodeFailedRef = useRef(false);

    const [speed, setSpeed] = useState<Speed>('steady');
    const [error, setError] = useState<string | null>(null);
    // Counters are mirrored into state so React can paint them; the
    // buffer itself stays in a ref because it changes hundreds of times
    // a second and none of that belongs in a render.
    const [shown, setShown] = useState(0);
    const [k, setK] = useState(0);
    const [startedAt] = useState(() => Date.now());
    const [elapsed, setElapsed] = useState(0);

    const fps = speed === 'steady' ? FPS_STEADY : FPS_SLOW;

    // ---- frame supply -------------------------------------------------

    /** Ask Rust for another bounded batch. Bounded, because each call is
     *  a real subprocess and a closed screen must not leave one running. */
    const requestBatch = useCallback(async () => {
        if (inFlightRef.current || exhaustedRef.current) return;
        inFlightRef.current = true;
        try {
            await Wizard.qrRender(
                operatorId,
                'shared',
                QR_BLOCK_SIZE,
                BATCH_FRAMES,
                // A fresh seed per batch: the LT degree/block choice is
                // seeded, so reusing one would replay the same frames
                // and stall a receiver that is missing a specific block.
                Math.floor(Math.random() * 0x7fffffff) + 1,
            );
        } catch (e) {
            // One failure is fatal to the supply: the pack is missing,
            // or the CLI is not there. Stop asking and say so — but
            // keep whatever frames we already have on screen, because
            // replaying those is still useful to the receiver.
            exhaustedRef.current = true;
            setError(String(e));
        } finally {
            inFlightRef.current = false;
        }
    }, [operatorId]);

    useEffect(() => {
        let unlisten: UnlistenFn | null = null;
        let dead = false;
        const stream = streamRef.current;
        (async () => {
            unlisten = await onQrFrame((f) => stream.push(f));
            if (dead) {
                unlisten?.();
                return;
            }
            void requestBatch();
        })();
        return () => {
            dead = true;
            exhaustedRef.current = true;
            unlisten?.();
        };
    }, [requestBatch]);

    // ---- the display tick ---------------------------------------------

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        const modules = paintedModules();
        const dpr = window.devicePixelRatio || 1;
        const px = modulePxFor(TARGET_CSS_PX, dpr);
        const side = modules * px;
        if (canvas.width !== side) {
            canvas.width = side;
            canvas.height = side;
            canvas.style.width = `${side / dpr}px`;
            canvas.style.height = `${side / dpr}px`;
        }

        const stream = streamRef.current;
        const tick = () => {
            if (encodeFailedRef.current) return;
            if (stream.needsMore && !exhaustedRef.current) void requestBatch();
            const frame = stream.next();
            if (frame === null) return; // nothing has arrived yet
            try {
                // Throws rather than silently drawing a different-sized
                // symbol if a frame ever arrives longer than the pinned
                // version holds; see paintFrame.
                paintFrame(ctx, frame, px);
            } catch (e) {
                encodeFailedRef.current = true;
                setError(String(e));
                return;
            }
            setShown(stream.shown);
            if (stream.k !== 0) setK(stream.k);
        };

        const id = window.setInterval(tick, Math.round(1000 / fps));
        return () => window.clearInterval(id);
    }, [fps, requestBatch]);

    useEffect(() => {
        const id = window.setInterval(
            () => setElapsed(Math.floor((Date.now() - startedAt) / 1000)),
            1000,
        );
        return () => window.clearInterval(id);
    }, [startedAt]);

    // Keep the screen awake. A transfer takes a minute or two of
    // holding still, which is exactly long enough for a phone to dim
    // and kill the symbol mid-stream. Best-effort: the API is absent in
    // some webviews and its absence must not break the screen.
    useEffect(() => {
        let sentinel: { release?: () => Promise<void> } | null = null;
        let released = false;
        const nav = navigator as unknown as {
            wakeLock?: { request: (kind: string) => Promise<typeof sentinel> };
        };
        nav.wakeLock
            ?.request('screen')
            .then((s) => {
                if (released) void s?.release?.();
                else sentinel = s;
            })
            .catch(() => {
                /* no wake lock here; the user holds the phone anyway */
            });
        return () => {
            released = true;
            try {
                void sentinel?.release?.();
            } catch {
                /* already gone */
            }
        };
    }, []);

    // ---- what the numbers mean ----------------------------------------

    const perPass = framesPerPass(k);
    const typical = framesTypical(k);
    const pass = perPass > 0 && shown > 0 ? Math.floor((shown - 1) / perPass) + 1 : 1;
    const inPass = perPass > 0 && shown > 0 ? ((shown - 1) % perPass) + 1 : 0;
    const passComplete = perPass > 0 && shown >= perPass;
    const pastTypical = typical > 0 && shown >= typical;

    let stateKey = 'qr.send.state.warming';
    if (passComplete) stateKey = 'qr.send.state.enough';
    else if (pastTypical) stateKey = 'qr.send.state.usual';
    else if (shown > 0) stateKey = 'qr.send.state.holding';

    const pct = perPass > 0 ? Math.min(100, (inPass / perPass) * 100) : 0;

    return (
        <Sheet
            title={t('qr.send.title')}
            onClose={onClose}
            width={520}
            footer={
                <Button variant="secondary" onClick={onClose} block>
                    {t('qr.send.done')}
                </Button>
            }
        >
            <div style={{ display: 'grid', gap: 12 }}>
                <div style={{ fontSize: 13, color: 'var(--muted)' }}>
                    {t('qr.send.what').replace('{relay}', relayName)}
                </div>

                {/* The symbol. White surround always: a QR is not a
                    themed element, and a dark-mode card behind a light
                    quiet zone is a scan failure waiting to happen. */}
                <div
                    style={{
                        display: 'flex',
                        justifyContent: 'center',
                        background: '#ffffff',
                        borderRadius: 'var(--r-card)',
                        padding: 8,
                    }}
                >
                    <canvas
                        ref={canvasRef}
                        role="img"
                        aria-label={t('qr.send.canvas.alt')}
                        style={{ display: 'block', imageRendering: 'pixelated' }}
                    />
                </div>

                <div style={{ display: 'grid', gap: 6 }}>
                    {/* Translated prose ("قاب {n} از {total}"), so no
                        font-mono: an inline fontFamily overrides the
                        RTL --font-fa rule and Persian has no glyphs in
                        the monospace stack. tabular-nums keeps the
                        counter from jittering without costing shaping. */}
                    <div
                        style={{
                            fontSize: 12,
                            fontVariantNumeric: 'tabular-nums',
                            display: 'flex',
                            justifyContent: 'space-between',
                            gap: 8,
                        }}
                    >
                        <span>
                            {perPass > 0
                                ? t('qr.send.progress')
                                      .replace('{n}', String(inPass))
                                      .replace('{total}', String(perPass))
                                : t('qr.send.progress.starting')}
                        </span>
                        <span style={{ color: 'var(--dim)' }}>
                            {t('qr.send.pass').replace('{n}', String(pass))}
                            {' · '}
                            {t('qr.send.elapsed').replace('{s}', String(elapsed))}
                        </span>
                    </div>
                    {/* A bar that fills once per pass. The tick mark is
                        where most receivers are already finished. */}
                    <div
                        style={{
                            position: 'relative',
                            height: 6,
                            borderRadius: 3,
                            background: 'var(--surface-2)',
                            overflow: 'hidden',
                        }}
                    >
                        <div
                            style={{
                                width: `${pct}%`,
                                height: '100%',
                                background: passComplete
                                    ? 'var(--green)'
                                    : 'var(--gold)',
                                transition: 'width 120ms linear',
                            }}
                        />
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                        {t(stateKey)}
                    </div>
                </div>

                <Card raised>
                    <div style={{ fontSize: 12, lineHeight: 1.6 }}>
                        {t('qr.send.how')}
                    </div>
                </Card>

                <div
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 8,
                        flexWrap: 'wrap',
                    }}
                >
                    <span style={{ fontSize: 12, color: 'var(--muted)' }}>
                        {t('qr.send.speed.label')}
                    </span>
                    <Segmented<Speed>
                        value={speed}
                        onChange={setSpeed}
                        items={[
                            { value: 'steady', label: t('qr.send.speed.steady') },
                            { value: 'slow', label: t('qr.send.speed.slow') },
                        ]}
                    />
                </div>

                {error && (
                    <Card>
                        <div
                            style={{
                                fontSize: 13,
                                color: 'var(--red)',
                                marginBottom: 6,
                            }}
                        >
                            {t('qr.send.error.title')}
                        </div>
                        <div
                            style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: 11,
                                color: 'var(--muted)',
                                wordBreak: 'break-word',
                            }}
                        >
                            {error}
                        </div>
                        <div style={{ fontSize: 12, marginTop: 8 }}>
                            {t('qr.send.error.body')}
                        </div>
                    </Card>
                )}
            </div>
        </Sheet>
    );
}
