// failureText — why something failed, in words a person can act on.
//
// Publisher commands reject with a Rust/Go error string. Showing that
// string as the message is how "context deadline exceeded" ends up in
// front of someone who wanted to send their mother a file. So the raw
// text is never the sentence: it is classified into one of a few plain
// explanations, and kept alongside as `detail` for the "Details"
// disclosure — still one tap away, because it is the only thing a
// maintainer can work from.

import { classifyPublisherError } from './wizardCommands';

export interface Failure {
    /** Plain words, already translated. */
    message: string;
    /** The untouched error text. Empty when there was none. */
    detail: string;
}

export function rawErrorText(e: unknown): string {
    if (typeof e === 'string') return e;
    if (e instanceof Error) return e.message;
    if (e == null) return '';
    try {
        return String(e);
    } catch {
        return '';
    }
}

/** True when the round-trip died before it reached the relay. */
export function looksUnreachable(msg: string): boolean {
    return /(context deadline exceeded|connection refused|i\/o timeout|no route to host|network is unreachable|timed out)/i.test(
        msg,
    );
}

/** Which plain explanation applies. Exported for the tests. */
export function failureKey(e: unknown): string {
    const raw = rawErrorText(e);
    switch (classifyPublisherError(e)) {
        case 'E_HELPER_IP_MISSING':
        case 'E_HELPER_IP_STALE':
            return 'pub.helper_ip.stale';
        case 'E_RELAY_TOO_OLD':
            return 'pub.rotate.too_old';
        case 'E_RELAY_KEYS_CHANGED':
            return 'pub.relay_keys_changed';
        case 'E_CUSTODY_LOCKED':
        case 'E_CUSTODY_WRONG_PASS':
        case 'E_CUSTODY_BACKEND':
        case 'E_LEGACY_PIN_REQUIRED':
        case 'E_SECRET_MISSING':
            return 'pub.fail.locked';
        case 'E_SETUP_RUNNING':
            return 'pub.fail.setup_running';
        case 'E_SERVER_EXISTS':
            return 'pub.fail.server_exists';
        case 'E_NOT_SUPPORTED':
            return 'pub.fail.not_supported';
        case 'E_RELAY_UNREACHABLE':
            return 'pub.fail.unreachable';
        case 'E_FILE_MISSING':
            return 'pub.fail.file_missing';
        case 'E_DEPLOY_TOO_OLD':
            return 'pub.fail.deploy_too_old';
        case 'E_RESTORE_UNFINISHED':
            // A restore committed and must finish before anything else.
            return 'pub.backup.err.unfinished';
        default:
            break;
    }
    if (looksUnreachable(raw)) return 'pub.fail.unreachable';
    return 'pub.fail.generic';
}

export function explainFailure(t: (k: string) => string, e: unknown): Failure {
    return { message: t(failureKey(e)), detail: rawErrorText(e) };
}

/** The same thing as one block of text, for the places that hold an
 *  error in a single string and render it `pre-line`: the explanation,
 *  a blank line, then the relay's own words. */
export function failureBlock(t: (k: string) => string, e: unknown): string {
    const f = explainFailure(t, e);
    return f.detail ? `${f.message}\n\n${f.detail}` : f.message;
}
