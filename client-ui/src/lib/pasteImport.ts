// pasteImport — one pasted link through the engine's uri_import, read
// the same way by the single-link flow (AddSheet) and the list
// (PasteList).
//
// The engine wraps a pasted link in a bundle signed with THIS phone's
// own sharing key (core/abi/share.go URIImport), so the only publisher it
// can name is this phone: the first paste ever comes back as a trust
// prompt (Kind=1) for that identity, and the answer is yes. A
// Kind=REJECTED verdict is a refusal, never "added".

import type { D2Contract } from '../contract/D2Contract';
import { errorText } from './errorText';
import { KIND_REJECTED, KIND_TRUST_PROMPT_NEEDED, friendlyReason, parseVerdict, trustFailure } from './importVerdict';
import { refusalCode } from './pasteItems';

type T = (k: string) => string;

export type LinkImport = { ok: true } | { ok: false; text: string };

/** The person's own words for a refused link. */
export function refusalText(t: T, raw: string): string {
    const key = `add.multi.refused.${refusalCode(raw)}`;
    const s = t(key);
    return s === key ? t('add.multi.refused.other') : s;
}

/** One link: imported and committed, or the plain reason it was not. */
export async function importLink(contract: Pick<D2Contract, 'uriImport' | 'resolveTrustPrompt'>, t: T, text: string): Promise<LinkImport> {
    try {
        const res = await contract.uriImport(text);
        if (res.error) return { ok: false, text: refusalText(t, res.error) };
        let v = parseVerdict(res.raw);
        if (v && v.Kind === KIND_TRUST_PROMPT_NEEDED && v.Fingerprint) {
            const raw = await contract.resolveTrustPrompt(v.Fingerprint, 0);
            const r = { decision: 0 as const, verdict: parseVerdict(raw), error: null };
            const fail = trustFailure(t, r);
            if (fail) return { ok: false, text: fail };
            v = r.verdict;
        }
        if (v && v.Kind === KIND_REJECTED) return { ok: false, text: friendlyReason(t, v.Reason || '') };
        return { ok: true };
    } catch (e) {
        return { ok: false, text: refusalText(t, errorText(e)) };
    }
}
