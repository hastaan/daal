// AddEntryModal.tsx — unified Add Route / Add Source flow (D-2 §5D).
// Four tabs: Paste / Scan-or-Drop / LAN / File. Shared component
// scoped to a `mode` prop that swaps copy and the underlying engine
// call between route-import and subscription-add.

import { useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import type { PreviewedBundle } from '../contract/D2Contract';
import TrustPrompt from './TrustPrompt';
import RecipientImport from '../recipient/RecipientImport';
import { Sheet, Button } from '../design/primitives';

type Mode = 'route' | 'source';
type Tab = 'paste' | 'scan' | 'lan' | 'file';

interface Props {
    t: (k: string) => string;
    mode: Mode;
    onClose: () => void;
}

export default function AddEntryModal({ t, mode, onClose }: Props) {
    const contract = useContract();
    const [tab, setTab] = useState<Tab>('paste');
    const [pasted, setPasted] = useState('');
    const [filePath, setFilePath] = useState('');
    const [preview, setPreview] = useState<PreviewedBundle | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [qrOpen, setQrOpen] = useState(false);

    const titleKey = mode === 'route' ? 'addroute.title' : 'addsource.title';

    const onChooseFile = async () => {
        // Real desktop builds wire @tauri-apps/plugin-dialog here.
        // The dev shell uses a plain text input.
    };

    const onPreview = async () => {
        setBusy(true);
        setError(null);
        try {
            const p = await contract.previewBundle(filePath);
            setPreview(p);
        } catch (e) {
            setError((e as Error).message || 'preview failed');
        } finally {
            setBusy(false);
        }
    };

    const onImport = async () => {
        setBusy(true);
        setError(null);
        try {
            if (mode === 'route') {
                await contract.importSbp(filePath);
            } else {
                await contract.subscriptionAdd({
                    publisherFingerprint: '',
                    url: pasted,
                    displayName: '',
                });
            }
            onClose();
        } catch (e) {
            setError((e as Error).message || 'import failed');
        } finally {
            setBusy(false);
        }
    };

    return (
        <Sheet
            title={t(titleKey)}
            onClose={onClose}
            width={640}
            footer={
                <>
                    <Button variant="ghost" onClick={onClose}>
                        {t('common.cancel')}
                    </Button>
                    <Button onClick={onImport} disabled={busy}>
                        {t('addroute.import')}
                    </Button>
                </>
            }
        >
                <div
                    role="tablist"
                    style={{
                        display: 'flex',
                        gap: 4,
                        background: 'var(--teal-deep)',
                        padding: 4,
                        borderRadius: 'var(--radius-md)',
                        marginBottom: 18,
                    }}
                >
                    {(['paste', 'scan', 'lan', 'file'] as Tab[]).map((k) => (
                        <button
                            key={k}
                            role="tab"
                            aria-selected={tab === k}
                            onClick={() => setTab(k)}
                            style={{
                                flex: 1,
                                background:
                                    tab === k
                                        ? 'var(--teal-raised)'
                                        : 'transparent',
                                border: 0,
                                color:
                                    tab === k
                                        ? 'var(--paper)'
                                        : 'var(--paper-dim)',
                                padding: '8px 10px',
                                borderRadius: 'var(--radius-md)',
                                cursor: 'pointer',
                                fontFamily: 'var(--font-body)',
                                fontSize: 13,
                            }}
                        >
                            {t(
                                mode === 'route'
                                    ? `addroute.tab.${k}`
                                    : `addsource.tab.${k}`,
                            )}
                        </button>
                    ))}
                </div>

                {tab === 'paste' && (
                    <textarea
                        value={pasted}
                        onChange={(e) => setPasted(e.target.value)}
                        placeholder={t(
                            mode === 'route'
                                ? 'addroute.preview.empty'
                                : 'subs.url_placeholder',
                        )}
                        rows={4}
                        style={inputStyle()}
                    />
                )}
                {tab === 'scan' && (
                    <div style={{ color: 'var(--paper-dim)', fontSize: 13 }}>
                        Scan a QR fountain (camera / clipboard / file).
                        <div style={{ marginTop: 10 }}>
                            <button
                                onClick={() => setQrOpen(true)}
                                style={btnSecondary()}
                            >
                                Open QR fountain
                            </button>
                        </div>
                    </div>
                )}
                {qrOpen && (
                    <RecipientImport
                        t={t}
                        onVerdict={() => {
                            setQrOpen(false);
                            onClose();
                        }}
                        onClose={() => setQrOpen(false)}
                    />
                )}
                {tab === 'lan' && (
                    <div style={{ color: 'var(--paper-dim)', fontSize: 13 }}>
                        LAN receive uses zero-config discovery on the local
                        network.
                    </div>
                )}
                {tab === 'file' && (
                    <div>
                        <input
                            value={filePath}
                            onChange={(e) => setFilePath(e.target.value)}
                            placeholder="/path/to/file.sbp"
                            style={inputStyle()}
                        />
                        <button
                            onClick={onChooseFile}
                            style={btnSecondary()}
                            disabled={busy}
                        >
                            {t('addroute.choose_file')}
                        </button>
                        <button
                            onClick={onPreview}
                            style={{ ...btnSecondary(), marginInlineStart: 8 }}
                            disabled={busy || !filePath}
                        >
                            {t('addroute.preview')}
                        </button>
                    </div>
                )}

                {preview && (
                    <TrustPrompt
                        t={t}
                        preview={preview}
                        onResolve={(decision) => {
                            if (decision === 0) {
                                onImport();
                            } else {
                                setPreview(null);
                            }
                        }}
                    />
                )}

                {error && (
                    <div
                        style={{
                            color: 'var(--danger)',
                            fontSize: 13,
                            marginTop: 10,
                        }}
                    >
                        {error}
                    </div>
                )}
        </Sheet>
    );
}

function inputStyle() {
    return {
        width: '100%',
        background: 'var(--teal-deep)',
        border: '1px solid var(--teal-border)',
        color: 'var(--paper)',
        padding: 10,
        borderRadius: 'var(--radius-md)',
        fontFamily: 'var(--font-body)',
        fontSize: 13,
        outline: 'none',
    } as const;
}
function btnSecondary() {
    return {
        background: 'var(--teal-raised)',
        border: '1px solid var(--teal-border)',
        color: 'var(--paper)',
        padding: '8px 14px',
        borderRadius: 'var(--radius-md)',
        fontFamily: 'var(--font-body)',
        fontSize: 13,
        cursor: 'pointer',
    } as const;
}
