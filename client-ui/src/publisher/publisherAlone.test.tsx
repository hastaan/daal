// Publisher-alone wave (D1-D5), UI side: a publisher with only a phone
// and no network knowledge must be told truthfully what exists, what
// costs money, and offered one safe button for each case.
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import wizardSource from './PublisherWizard.tsx?raw';
import qrSource from './QrSendSheet.tsx?raw';
import pageSource from './PublisherRecipientsPage.tsx?raw';
import listSource from './RelayListPage.tsx?raw';
import rebuildSource from './RelayRebuild.tsx?raw';
import recoverCardSource from './SetupRecoveryCard.tsx?raw';
import accountSheetSource from './AccountCheckSheet.tsx?raw';
import renewSheetSource from './RenewSheet.tsx?raw';
import healthPanelSource from './HealthPanel.tsx?raw';
import addrSource from './DestroyAddresses.tsx?raw';
import {
    DESTRUCTIVE,
    buttonKey,
    cancelPlan,
    checkErrorKey,
    confirmKey,
    kindKey,
    afterRecovery,
    cancelBodyKey,
    cancelDelete,
    existingAfterFailure,
    isMissingCommand,
    performRecovery,
    recoveryCheckFailed,
    recoveryFixture,
    recoveryView,
} from './setupRecovery';
import { releaseRetryFor, retryRelease, stillBills } from './destroyReport';
import { renewBannerText } from './renew';
import { qrErrorBody } from './QrSendSheet';
import { healthFailure } from './relayHealth';
import { dateLabel } from './SetupRecoveryCard';
import type { RecoveryButton } from './setupRecovery';
import { CancelSetupSheet, SetupRecoveryCard } from './SetupRecoveryCard';
import {
    accountFixture,
    defaultSelection,
    deletable,
    errorKey,
    groupOf,
    outcomeKey,
    selectedRefs,
} from './accountCheck';
import { AccountBlock } from './AccountCheckSheet';
import { renewBannerVisible, renewFixture, renewTargets, reasonKey, statusKey } from './renew';
import { RenewResultRow, renewFailure } from './RenewSheet';
import {
    checkHealth,
    checkSequentially,
    checkedWorking,
    familyNameKey,
    healthFixture,
    healthLines,
    managementLineKey,
    overallKey,
    serverLineKey,
    wayStateKey,
} from './relayHealth';
import { HealthPanel } from './HealthPanel';
import { AddressLines, UnreleasedAddresses, addressLineKey, addressLineText, retryNeeded } from './DestroyAddresses';
import { relayBadge } from './relayStatus';
import { DensityProvider } from '../design/DensityProvider';
import { failureKey } from './failureText';
import { classifyPublisherError, recipientArtifact, serverIdFromExists } from './wizardCommands';
import type {
    AccountCleanupCode,
    AddressOutcome,
    DestroyReport,
    RecipientSummary,
    RelayHealth,
    RenewItem,
    SetupRecovery,
} from './wizardCommands';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const t = (k: string) => EN[k] ?? `MISSING:${k}`;

function report(over: Partial<DestroyReport> = {}): DestroyReport {
    return {
        server_deleted: true,
        ssh_key_deleted: true,
        firewall_deleted: true,
        local_removed: false,
        warnings: [],
        addresses: [],
        retry_needed: false,
        ...over,
    };
}

function deps(rep: DestroyReport = report()) {
    return {
        runBuild: vi.fn((_id?: string) => undefined),
        setupRemoveServer: vi.fn(async (_op: number) => rep),
        relayDestroy: vi.fn(async (_op: number, _del: boolean, _own?: boolean) => rep),
        setExisting: vi.fn((_id: string | null) => undefined),
    };
}

const STATES: SetupRecovery['state'][] = [
    'none',
    'running',
    'finished_unsaved',
    'server_running',
    'nothing_billing',
    'unknown',
];

// ---------------------------------------------------------------- D1

describe('D1 interrupted setup: one card per state', () => {
    const table: [string, SetupRecovery, RecoveryButton[]][] = [
        ['none', recoveryFixture('none'), ['start']],
        ['running', recoveryFixture('running'), ['check_again']],
        ['finished_unsaved', recoveryFixture('finished_unsaved'), ['continue']],
        ['server_running hetzner', recoveryFixture('server_running'), ['finish_here', 'delete_server']],
        [
            'server_running vultr',
            recoveryFixture('server_running', { provider: 'vultr', can_finish_here: false }),
            ['delete_and_rebuild', 'delete_and_stop'],
        ],
        ['server_running yours', recoveryFixture('server_running', { server_origin: 'yours' }), ['finish_yours']],
        ['nothing_billing', recoveryFixture('nothing_billing'), ['start_again']],
        ['unknown', recoveryFixture('unknown'), ['check_again', 'delete_whatever']],
    ];

    it.each(table)('%s offers exactly its buttons, and draws them', (_n, rec, buttons) => {
        expect(recoveryView(rec).buttons).toEqual(buttons);
        const html = renderToStaticMarkup(
            <SetupRecoveryCard t={t} rec={rec} busy={false} error={null} outcome={null} onButton={() => {}} />,
        );
        expect(html).toContain(`data-state="${rec.state}"`);
        for (const b of buttons) {
            expect(html).toContain(`data-button="${b}"`);
            expect(html).toContain(t(buttonKey(b)).replace(/'/g, '&#x27;'));
        }
        expect(html).not.toContain('MISSING:');
    });

    it('loading says it is checking and offers nothing', () => {
        const v = recoveryView(null);
        expect(v.buttons).toEqual([]);
        expect(t(v.titleKey)).toBe('Checking your hosting account…');
    });

    it('a running server is described with its address and as costing money', () => {
        const html = renderToStaticMarkup(
            <SetupRecoveryCard
                t={t}
                rec={recoveryFixture('server_running')}
                busy={false}
                error={null}
                outcome={null}
                onButton={() => {}}
            />,
        );
        expect(html).toContain('already running and costing money');
        expect(html).toContain('203.0.113.7');
        // No date in the journal: no dangling "started".
        const noDate = recoveryView(recoveryFixture('server_running', { started_at_unix: 0 }));
        expect(t(noDate.titleKey)).not.toContain('{date}');
    });

    it('the Vultr card says the hosting company cannot finish, and its confirm says a new server is rented', () => {
        const v = recoveryView(recoveryFixture('server_running', { provider: 'vultr', can_finish_here: false }));
        expect(v.bodyKeys.map(t).join(' ')).toContain("can't finish setup on it");
        expect(t(confirmKey('delete_and_rebuild'))).toMatch(/rents a NEW server/);
    });

    it('every delete goes through a confirm; nothing else does', () => {
        expect([...DESTRUCTIVE].sort()).toEqual(
            ['delete_and_rebuild', 'delete_and_stop', 'delete_server', 'delete_whatever'].sort(),
        );
    });

    it('each unknown reason has its own sentence', () => {
        for (const c of ['no_token', 'offline', 'account_unreadable', 'custody_locked', 'failed'] as const) {
            expect(EN[checkErrorKey(c)], c).toBeTruthy();
        }
    });

    it('start / continue / start again build without a server id', async () => {
        for (const b of ['start', 'continue', 'start_again'] as RecoveryButton[]) {
            const d = deps();
            expect((await performRecovery(b, 7, recoveryFixture('none'), d)).kind).toBe('build');
            expect(d.runBuild).toHaveBeenCalledWith();
            expect(d.setupRemoveServer).not.toHaveBeenCalled();
            expect(d.relayDestroy).not.toHaveBeenCalled();
        }
    });

    it('finish here builds ON the server that exists (no second server)', async () => {
        const d = deps();
        await performRecovery('finish_here', 7, recoveryFixture('server_running'), d);
        expect(d.runBuild).toHaveBeenCalledWith('123');
        const d2 = deps();
        await performRecovery(
            'finish_yours',
            7,
            recoveryFixture('server_running', { server_origin: 'yours', server_id: '555' }),
            d2,
        );
        expect(d2.runBuild).toHaveBeenCalledWith('555');
    });

    it('delete this server removes the cloud side and keeps the relay', async () => {
        const d = deps();
        const r = await performRecovery('delete_server', 7, recoveryFixture('server_running'), d);
        expect(d.setupRemoveServer).toHaveBeenCalledWith(7);
        expect(d.relayDestroy).not.toHaveBeenCalled();
        expect(d.runBuild).not.toHaveBeenCalled();
        expect(r).toMatchObject({ kind: 'deleted', relayGone: false });
    });

    it('delete and build a new one rents only once the old one is proven gone', async () => {
        const ok = deps(report({ server_deleted: true }));
        await performRecovery('delete_and_rebuild', 7, recoveryFixture('server_running'), ok);
        expect(ok.setupRemoveServer).toHaveBeenCalledWith(7);
        expect(ok.runBuild).toHaveBeenCalledWith();
        const kept = deps(report({ server_deleted: false }));
        const r = await performRecovery('delete_and_rebuild', 7, recoveryFixture('server_running'), kept);
        expect(kept.runBuild).not.toHaveBeenCalled();
        expect(r).toMatchObject({ kind: 'deleted', thenBuild: false });
    });

    it('delete and build a new one does not rent while an address still bills, and the card keeps Try again', async () => {
        const kept = deps(
            report({
                server_deleted: true,
                retry_needed: true,
                addresses: [{ id: '42', ip: '198.51.100.9', released: false, code: 'release_failed' }],
            }),
        );
        const r = await performRecovery('delete_and_rebuild', 7, recoveryFixture('server_running'), kept);
        expect(kept.runBuild).not.toHaveBeenCalled();
        expect(r).toMatchObject({ kind: 'deleted', thenBuild: false });
        expect(afterRecovery('delete_and_rebuild', r)).toEqual({ requery: true, leave: false });
        const html = renderToStaticMarkup(
            <SetupRecoveryCard
                t={t}
                rec={recoveryFixture('nothing_billing', { billing: 'yes' })}
                busy={false}
                error={null}
                outcome={(r as { report: DestroyReport }).report}
                onButton={() => {}}
                onRetry={() => {}}
            />,
        );
        expect(html).toContain('198.51.100.9 is still reserved');
        expect(html).toContain(EN['pub.relays.destroy.addr.retry']);
    });

    it('every button sets or clears the server to finish on; a deleted one never rides along', async () => {
        for (const b of ['start', 'continue', 'start_again', 'delete_server', 'delete_and_rebuild', 'delete_and_stop', 'delete_whatever'] as RecoveryButton[]) {
            const d = deps();
            await performRecovery(b, 7, recoveryFixture('server_running'), d);
            expect(d.setExisting, b).toHaveBeenCalledWith(null);
        }
        const d = deps();
        await performRecovery('finish_here', 7, recoveryFixture('server_running'), d);
        expect(d.setExisting).toHaveBeenCalledWith('123');
        // A failed finish-here was rolled back (its server deleted):
        // forget the id. The person's own server is never rolled back.
        expect(existingAfterFailure('123', 'created')).toBeNull();
        expect(existingAfterFailure('555', 'yours')).toBe('555');
        expect(wizardSource).toContain('setUseExisting((cur) => existingAfterFailure(cur, origin))');
    });

    it('a delete that removes the relay keeps its report on the card until Done; nothing asks again', async () => {
        const gone = deps(report({ local_removed: true }));
        const r = await performRecovery('delete_and_stop', 9, recoveryFixture('server_running'), gone);
        expect(afterRecovery('delete_and_stop', r)).toEqual({ requery: false, leave: true });
        const html = renderToStaticMarkup(
            <SetupRecoveryCard
                t={t}
                rec={recoveryFixture('server_running')}
                busy={false}
                error={null}
                outcome={report({ local_removed: true, addresses: [{ id: '1', ip: '198.51.100.1', released: true, code: 'released' }] })}
                onButton={() => {}}
                onDone={() => {}}
            />,
        );
        expect(html).toContain('data-button="done"');
        expect(html).toContain('198.51.100.1 released');
        expect(html).not.toContain('data-button="finish_here"');
        // The wizard does not reset in the same tick as the delete.
        const press = wizardSource.slice(wizardSource.indexOf('const onRecoveryButton'), wizardSource.indexOf('function resetAfterCancel'));
        expect(press).not.toContain('resetAfterCancel()');
        const cancel = wizardSource.slice(wizardSource.indexOf('const onCancelDelete'), wizardSource.indexOf('const onCancelKeep'));
        expect(cancel).not.toContain('resetAfterCancel()');
        // The cancel sheet shows the report with Done once the relay is gone.
        const sheet = renderToStaticMarkup(
            <DensityProvider><CancelSetupSheet
                t={t}
                rec={recoveryFixture('server_running')}
                busy={false}
                outcome={report({ local_removed: true, addresses: [{ id: '3', ip: '198.51.100.3', released: false, code: 'not_daal' }] })}
                error={null}
                onDelete={() => {}}
                onKeep={() => {}}
                onCheckAgain={() => {}}
                onClose={() => {}}
                onDone={() => {}}
            /></DensityProvider>,
        );
        expect(sheet).toContain('data-button="done"');
        expect(sheet).toContain('You reserved 198.51.100.3 yourself');
        expect(sheet).not.toContain('data-button="delete"');
    });

    it('the server is gone but an address still bills: never "nothing is costing money"', () => {
        const rec = recoveryFixture('nothing_billing', {
            billing: 'yes',
            leftovers: [{ kind: 'floating-ip', id: '42', name: 'daal-fsn1-00-ip', billing: true }],
        });
        const v = recoveryView(rec);
        expect(v.titleKey).toBe('pub.setup.recover.address_kept');
        expect(v.buttons).toEqual(['delete_server', 'start_again']);
        expect(v.billing).toBe(true);
        expect(cancelBodyKey(rec)).toBe('pub.setup.cancel.body.address_kept');
        const html = renderToStaticMarkup(
            <SetupRecoveryCard t={t} rec={rec} busy={false} error={null} outcome={null} onButton={() => {}} />,
        );
        expect(html).not.toContain(EN['pub.setup.recover.nothing_billing']);
        expect(html).toContain('daal-fsn1-00-ip');
        expect(recoveryView(recoveryFixture('nothing_billing')).titleKey).toBe('pub.setup.recover.nothing_billing');
    });

    it('only a missing command falls back to the old card; any other failure is "could not check"', () => {
        expect(isMissingCommand('Command wizard_setup_recovery not found')).toBe(true);
        expect(isMissingCommand('database is locked')).toBe(false);
        expect(isMissingCommand('E_CUSTODY_LOCKED: locked')).toBe(false);
        const r = recoveryCheckFailed('database is locked');
        expect(r.state).toBe('unknown');
        expect(recoveryView(r).buttons).toEqual(['check_again', 'delete_whatever']);
        expect(wizardSource).toContain('if (isMissingCommand(e))');
    });

    it('the start date is shown in the phone\'s own time zone', () => {
        const unix = 1_763_546_400;
        expect(dateLabel(unix)).toBe(
            new Date(unix * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }),
        );
        expect(healthPanelSource).not.toContain('toISOString');
    });

    it('delete and stop / delete whatever was made call relayDestroy(op, true)', async () => {
        for (const b of ['delete_and_stop', 'delete_whatever'] as RecoveryButton[]) {
            const d = deps(report({ local_removed: true }));
            const r = await performRecovery(b, 9, recoveryFixture('unknown'), d);
            expect(d.relayDestroy).toHaveBeenCalledWith(9, true);
            expect(r).toMatchObject({ kind: 'deleted', relayGone: true });
        }
    });

    it('check again only asks again', async () => {
        const d = deps();
        expect((await performRecovery('check_again', 1, recoveryFixture('running'), d)).kind).toBe('requery');
        expect(d.runBuild).not.toHaveBeenCalled();
    });

    it('a provision refused with E_SERVER_EXISTS or E_SETUP_RUNNING goes back to the card, never to a retry', () => {
        expect(classifyPublisherError('E_SERVER_EXISTS: 123 server already exists')).toBe('E_SERVER_EXISTS');
        expect(serverIdFromExists('E_SERVER_EXISTS: 123 server already exists')).toBe('123');
        expect(serverIdFromExists('E_OTHER: 123')).toBe('');
        const i = wizardSource.indexOf("code === 'E_SERVER_EXISTS' || code === 'E_SETUP_RUNNING'");
        expect(i).toBeGreaterThan(0);
        expect(wizardSource.slice(i, i + 600)).toContain('setAwaitingBuildConsent(true)');
    });
});

describe('D1 cancel offers deletion', () => {
    it('with a token and anything rented, cancel deletes; never local-only', () => {
        expect(cancelPlan(recoveryFixture('server_running'))).toBe('delete');
        expect(cancelPlan(recoveryFixture('unknown'))).toBe('delete');
        expect(cancelPlan(recoveryFixture('nothing_billing'))).toBe('delete');
        expect(cancelPlan(recoveryFixture('running'))).toBe('wait');
        expect(cancelPlan(recoveryFixture('server_running', { server_origin: 'yours' }))).toBe('yours_choice');
        expect(cancelPlan(recoveryFixture('none'))).toBe('local');
        expect(cancelPlan(recoveryFixture('unknown', { check_error: 'no_token' }))).toBe('local');
        expect(cancelPlan(null)).toBe('local');
    });

    it('the cancel delete calls relayDestroy(op, true), and the local cancel is only the fallback', async () => {
        const rd = vi.fn(async (_op: number, _del: boolean, _own?: boolean) => report({ local_removed: true }));
        const r = await cancelDelete(4, 'delete', rd);
        expect(rd).toHaveBeenCalledWith(4, true, false);
        expect(r.relayGone).toBe(true);
        // "Delete my server" is the only path that may take the person's
        // own server.
        await cancelDelete(4, 'yours_choice', rd);
        expect(rd).toHaveBeenLastCalledWith(4, true, true);
        const body = wizardSource.slice(wizardSource.indexOf('const onCancelDelete'));
        expect(body.slice(0, 700)).toContain('cancelDelete(operatorId, cancelPlan(cancelRec)');
        const press = wizardSource.slice(wizardSource.indexOf('const onCancelPress'), wizardSource.indexOf('const onCancelDelete'));
        // The local-only cancel runs only after the plan said local.
        expect(press.indexOf("cancelPlan(rec) !== 'local'")).toBeGreaterThan(0);
        expect(press.indexOf("cancelPlan(rec) !== 'local'")).toBeLessThan(press.indexOf('cancelAndCleanup'));
        // A failed look with a token stored is "unknown", not local.
        expect(press).toContain("recoveryFixture('unknown'");
        // The Cancel button goes through that plan, not straight to the
        // local-only cleanup.
        expect(wizardSource).toContain('onClick={() => void onCancelPress()}');
    });

    it('the cancel sheet names what goes, and for your own server offers keep or delete', () => {
        const html = renderToStaticMarkup(
            <DensityProvider><CancelSetupSheet
                t={t}
                rec={recoveryFixture('server_running')}
                busy={false}
                outcome={null}
                error={null}
                onDelete={() => {}}
                onKeep={() => {}}
                onCheckAgain={() => {}}
                onClose={() => {}}
                onDone={() => {}}
            /></DensityProvider>,
        );
        expect(html).toContain('data-plan="delete"');
        expect(html).toContain('daal-fsn1-0011223344556677');
        expect(html).toContain('costs money');
        const mine = renderToStaticMarkup(
            <DensityProvider><CancelSetupSheet
                t={t}
                rec={recoveryFixture('server_running', { server_origin: 'yours' })}
                busy={false}
                outcome={null}
                error={null}
                onDelete={() => {}}
                onKeep={() => {}}
                onCheckAgain={() => {}}
                onClose={() => {}}
                onDone={() => {}}
            /></DensityProvider>,
        );
        expect(mine).toContain('data-button="keep"');
        expect(mine).toContain('data-button="delete"');
        expect(t('pub.setup.cancel.keep_mine.line')).toMatch(/costing money/);
    });
});

describe('D1 account check', () => {
    it('sorts items into the groups the person reads', () => {
        const acc = accountFixture();
        const g = Object.fromEntries(acc.items.map((i) => [i.id, groupOf(i)]));
        expect(g).toEqual({
            '10': 'in_use',
            '11': 'billing_unused',
            '12': 'billing_unused',
            '42': 'billing_unused',
            '901': 'free_leftovers',
            '13': 'unfinished',
            '14': 'cannot_tell',
        });
    });

    it('never offers to delete in-use, unfinished or cannot-tell, even if the shell says can_delete', () => {
        const acc = accountFixture();
        const ids = [...defaultSelection(acc)].sort();
        expect(ids).toEqual(['floating-ip:42', 'server:11', 'server:12', 'ssh-key:901']);
        expect(deletable(acc, acc.items.find((i) => i.id === '14')!)).toBe(false);
        expect(selectedRefs(acc, new Set(['server:14', 'server:10', 'server:13']))).toEqual([]);
    });

    it('an incomplete account offers nothing to delete and says why', () => {
        const acc = accountFixture({ complete: false, error_code: 'offline' });
        expect(defaultSelection(acc).size).toBe(0);
        const html = renderToStaticMarkup(
            <AccountBlock t={t} acc={acc} selection={new Set()} onToggle={() => {}} />,
        );
        expect(html).not.toContain('type="checkbox"');
        expect(html).toContain('nothing can be deleted safely');
        expect(html).toContain(t(errorKey('offline')));
    });

    it('a complete account has checkboxes for exactly the deletable items, and warns about another phone', () => {
        const acc = accountFixture();
        const html = renderToStaticMarkup(
            <AccountBlock t={t} acc={acc} selection={defaultSelection(acc)} onToggle={() => {}} />,
        );
        expect(html.match(/type="checkbox"/g)?.length).toBe(4);
        expect(html).toContain('If you set this up from another phone, people using it will be cut off.');
        expect(html).not.toContain('MISSING:');
    });

    it('the sheet states the rule once, and the list opens from the relay list when a token is stored', () => {
        expect(EN['pub.account.rule']).toBe(
            'Daal only offers to delete things it labelled as its own when it made them. Nothing else in your account is touched.',
        );
        expect(accountSheetSource.match(/pub\.account\.rule/g)?.length).toBe(1);
        expect(listSource).toContain("o.has_cloud_token === true");
        expect(listSource).toContain('<AccountCheckSheet');
    });

    it('every cleanup outcome has a plain sentence', () => {
        const codes: AccountCleanupCode[] = [
            'deleted',
            'released',
            'kept_in_use',
            'kept_claimed',
            'kept_not_daal',
            'kept_unproven',
            'kept_list_unreadable',
            'kept_unsupported',
            'delete_failed',
            'already_gone',
        ];
        for (const c of codes) expect(EN[outcomeKey(c)], c).toBeTruthy();
    });

    it('the relay list marks an interrupted setup and opens it', () => {
        expect(listSource).toContain("op.setup_interrupted === true");
        expect(EN['pub.relays.interrupted']).toMatch(/costing money/);
    });
});

// ---------------------------------------------------------------- D2

function person(id: number, over: Partial<RecipientSummary> = {}): RecipientSummary {
    return {
        id,
        name: `r${id}`,
        display_name: `Person ${id}`,
        address_str: `daal1q${id}`,
        provisioned_at_unix: 1,
        revoked_at_unix: 0,
        ...over,
    } as RecipientSummary;
}

describe('D2 renew everyone', () => {
    const op = { status: 'provisioned', people_needing_renewal: 0 };

    it('the banner shows after a rebuild, when people need renewing, or when the check finds people missing', () => {
        expect(renewBannerVisible(op, null, false)).toBe(false);
        expect(renewBannerVisible(op, null, true)).toBe(true);
        expect(renewBannerVisible({ ...op, people_needing_renewal: 2 }, null, false)).toBe(true);
        expect(renewBannerVisible(op, { people_missing: 1, everyone_missing: false }, false)).toBe(true);
        expect(renewBannerVisible(op, { people_missing: 0, everyone_missing: true }, false)).toBe(true);
        expect(renewBannerVisible({ status: 'rebuild_failed', people_needing_renewal: 3 }, null, true)).toBe(false);
        expect(EN['pub.renew.banner']).toBe('The server is new, so the files you gave people stopped working.');
    });

    it('the banner claims "the server is new" only after a rebuild; a health finding says how many', () => {
        expect(renewBannerText({ people_needing_renewal: 2 }, null, false).key).toBe('pub.renew.banner');
        expect(renewBannerText({ people_needing_renewal: 0 }, null, true).key).toBe('pub.renew.banner');
        const one = renewBannerText({ people_needing_renewal: 0 }, { people_missing: 1, everyone_missing: false }, false);
        expect(one.key).toBe('pub.renew.banner.missing_one');
        const three = renewBannerText({ people_needing_renewal: 0 }, { people_missing: 3, everyone_missing: false }, false);
        expect(three).toEqual({ key: 'pub.renew.banner.missing', n: 3 });
        expect(EN['pub.renew.banner.missing']).toContain('{n}');
        expect(renewBannerText({ people_needing_renewal: 0 }, { people_missing: 0, everyone_missing: true }, false).key).toBe(
            'pub.renew.banner.everyone_missing',
        );
        for (const k of ['pub.renew.banner.missing', 'pub.renew.banner.missing_one', 'pub.renew.banner.everyone_missing']) {
            expect(EN[k]).not.toMatch(/server is new/);
        }
    });

    it('the confirm names only people whose access was not removed, and says removed stay removed', () => {
        expect(renewTargets([person(1), person(2, { revoked_at_unix: 5 }), person(3)]).map((r) => r.id)).toEqual([1, 3]);
        expect(EN['pub.renew.removed_stay_removed']).toBe('People you removed stay removed.');
    });

    it('a done row keeps share and save and adds QR and copy; a failed row says why in plain words', () => {
        const rep = renewFixture();
        const send = { onSend: vi.fn(), onSave: vi.fn(), onQr: vi.fn(), onCopy: vi.fn() };
        const done = renderToStaticMarkup(<RenewResultRow t={t} item={rep.items[0]} send={send} />);
        for (const k of ['pub.people.send', 'pub.people.save', 'pub.person.qr', 'pub.person.copy']) {
            expect(done).toContain(t(k));
        }
        const failed = renderToStaticMarkup(<RenewResultRow t={t} item={rep.items[2]} send={send} />);
        expect(failed).toContain('The relay has no room for more people.');
        expect(failed).not.toContain(t('pub.person.qr'));
        // The raw text sits in Details only.
        expect(failed.indexOf('mgmt: 507')).toBeGreaterThan(failed.indexOf('<details'));
    });

    it('every status and reason has a sentence', () => {
        const statuses: (RenewItem['status'] | 'working')[] = [
            'working',
            'done',
            'already_done',
            'failed',
            'not_attempted',
            'removed_from_server',
        ];
        for (const s of statuses) expect(EN[statusKey(s)], s).toBeTruthy();
        for (const r of ['relay_unreachable', 'relay_full', 'relay_too_old', 'file_write_failed', 'signing_failed', 'other'] as const) {
            expect(EN[reasonKey(r)], r).toBeTruthy();
        }
    });

    it('"nothing was changed" is said only for E_RELAY_UNREACHABLE', () => {
        expect(renewFailure(t, 'E_RELAY_UNREACHABLE: list failed').message).toBe(EN['pub.renew.failed']);
        expect(renewFailure(t, 'E_DEPLOY_TOO_OLD: unknown subcommand').message).toBe(EN['pub.fail.deploy_too_old']);
    });

    it('after a rebuild the per-person instruction is gone and the renew button is offered', () => {
        const done = rebuildSource.slice(rebuildSource.indexOf("t('pub.danger.rebuild.done.body')"));
        expect(done.slice(0, 900)).not.toContain('pub.danger.rebuild.done.by_hand');
        expect(rebuildSource).toContain("t('pub.renew.action')");
        expect(pageSource).toContain('Wizard.renewEveryone(operatorId)');
    });
});

// ---------------------------------------------------------------- D3

describe('D3 health check', () => {
    const now = 1_800_000_000;

    it('green only when the last check said working and is fresh', () => {
        expect(checkedWorking(healthFixture({ checked_at_unix: now - 60 }), now)).toBe(true);
        expect(checkedWorking(healthFixture({ checked_at_unix: now - 601 }), now)).toBe(false);
        expect(checkedWorking(healthFixture({ checked_at_unix: now, overall: 'partly' }), now)).toBe(false);
        expect(checkedWorking(null, now)).toBe(false);
        expect(relayBadge('provisioned', checkedWorking(healthFixture({ checked_at_unix: now }), now)).tone).toBe('good');
        expect(relayBadge('provisioned', checkedWorking(healthFixture({ checked_at_unix: now - 3600 }), now)).tone).not.toBe('good');
    });

    it('lines are plain words, ways named by plain name, never the protocol token', () => {
        const h = healthFixture({
            ways: [
                { family: 'vless-reality', state: 'answers' },
                { family: 'naive', state: 'wrong_server' },
                { family: 'tuic', state: 'not_testable_here' },
                { family: 'mystery-proto', state: 'no_answer' },
            ],
            keys_match: false,
            people_missing: 2,
        });
        const html = renderToStaticMarkup(
            <HealthPanel t={t} health={h} busy={false} failed={null} now={h.checked_at_unix} onCheck={() => {}} />,
        );
        for (const raw of ['vless', 'reality', 'naive', 'tuic', 'mystery-proto']) {
            expect(html.toLowerCase()).not.toContain(raw);
        }
        expect(html).toContain('answered as a different server');
        expect(html).toContain("can&#x27;t be tested from this phone");
        expect(html).toContain(EN['pub.health.keys_changed'].replace(/'/g, '&#x27;'));
        expect(html).toContain('2 of the people you gave files to are not on the server');
        // The honest limit, once.
        expect(html.split(EN['pub.health.limits']).length - 1).toBe(1);
        expect(EN['pub.health.limits']).toMatch(/Nobody outside the country/);
    });

    it('keys_changed is serious; the address hint gets its own sentence', () => {
        const lines = healthLines(t, healthFixture({ keys_match: false }));
        expect(lines.find((l) => l.key === 'pub.health.keys_changed')?.serious).toBe(true);
        expect(
            managementLineKey(healthFixture({ management: 'no_answer', management_reason: 'address_may_have_changed' })),
        ).toBe('pub.health.mgmt.address_changed');
    });

    it('re-detects the phone address once and re-runs, never more', async () => {
        const stale = healthFixture({ management: 'no_answer', management_reason: 'address_may_have_changed' });
        const relayHealth = vi.fn(async (_op: number, _f: boolean) => stale);
        const reAllowlist = vi.fn(async (_op: number) => '198.51.100.1');
        const h = await checkHealth(3, false, {
            relayHealth,
            reAllowlist,
            storedHelperIp: async () => '203.0.113.50',
            withHelperIp: (_op, fn) => fn(),
        });
        expect(relayHealth.mock.calls).toEqual([
            [3, false],
            [3, true],
        ]);
        expect(reAllowlist).toHaveBeenCalledTimes(1);
        // The new address did not help either: no longer blamed on it.
        expect(h.management_reason).toBe('timeout');
    });

    it('a cached result, or an address that did not change, never forces another check', async () => {
        const stale = healthFixture({ management: 'no_answer', management_reason: 'address_may_have_changed' });
        const cached = { ...stale, from_cache: true };
        const relayHealth = vi.fn(async (_op: number, _f: boolean) => cached);
        const reAllowlist = vi.fn(async (_op: number) => '198.51.100.1');
        const deps = { relayHealth, reAllowlist, storedHelperIp: async () => '198.51.100.1', withHelperIp: <T,>(_op: number, fn: () => Promise<T>) => fn() };
        await checkHealth(3, false, deps);
        expect(relayHealth.mock.calls).toEqual([[3, false]]);
        expect(reAllowlist).not.toHaveBeenCalled();
        relayHealth.mockImplementation(async () => stale);
        const same = await checkHealth(3, false, deps);
        expect(relayHealth.mock.calls).toEqual([[3, false], [3, false]]);
        expect(same.management_reason).toBe('timeout');
    });

    it('a check that could not run says why: update the app, not try again', () => {
        expect(healthFailure(t, 'E_DEPLOY_TOO_OLD: no relay-health').message).toBe(EN['pub.fail.deploy_too_old']);
        expect(healthFailure(t, 'something odd').message).toBe(EN['pub.health.could_not_check']);
        expect(healthFailure(t, 'E_DEPLOY_TOO_OLD: x').detail).toContain('E_DEPLOY_TOO_OLD');
    });

    it('checks relays one after another, and one failure does not stop the next', async () => {
        const order: string[] = [];
        let inFlight = 0;
        await checkSequentially(
            [1, 2, 3],
            async (op) => {
                inFlight += 1;
                expect(inFlight).toBe(1);
                order.push(`start${op}`);
                await Promise.resolve();
                inFlight -= 1;
                if (op === 2) throw new Error('x');
                return healthFixture({ operator_id: op });
            },
            (op, h) => order.push(`${op}:${h ? 'ok' : 'null'}`),
        );
        expect(order).toEqual(['start1', '1:ok', 'start2', '2:null', 'start3', '3:ok']);
    });

    it('the list and the relay page run it on open; Check now forces it', () => {
        expect(listSource).toContain('checkHealth(id, false)');
        expect(pageSource).toContain('void runHealth(false)');
        expect(pageSource).toContain('onCheck={() => void runHealth(true)}');
    });
});

// ---------------------------------------------------------------- D4

describe('D4 delete releases every reserved address', () => {
    const addrs: AddressOutcome[] = [
        { id: '1', ip: '198.51.100.1', released: true, code: 'released' },
        { id: '2', ip: '198.51.100.2', released: false, code: 'release_failed' },
        { id: '3', ip: '198.51.100.3', released: false, code: 'not_daal' },
    ];

    it('one line per address; a failed release offers Try again', () => {
        const html = renderToStaticMarkup(<AddressLines t={t} addresses={addrs} onRetry={() => {}} />);
        expect(html).toContain('Address 198.51.100.1 released, it no longer costs money.');
        expect(html).toContain('Address 198.51.100.2 is still reserved and still costs money.');
        expect(html).toContain('You reserved 198.51.100.3 yourself');
        expect(html).toContain(EN['pub.relays.destroy.addr.retry']);
        const clean = renderToStaticMarkup(<AddressLines t={t} addresses={[addrs[0], addrs[2]]} onRetry={() => {}} />);
        expect(clean).not.toContain(EN['pub.relays.destroy.addr.retry']);
    });

    it('retry_needed or a failed address means billing has not stopped', () => {
        expect(retryNeeded(report({ addresses: [addrs[1]] }))).toBe(true);
        expect(retryNeeded(report({ retry_needed: true }))).toBe(true);
        expect(retryNeeded(report({ addresses: [addrs[0], addrs[2]] }))).toBe(false);
        expect(listSource).toContain("pub.relays.destroy.addr.server_gone_address_kept");
    });

    it('a relay card with unreleased addresses names them with Try again', () => {
        const html = renderToStaticMarkup(<UnreleasedAddresses t={t} ips={['198.51.100.9']} onRetry={() => {}} />);
        expect(html).toContain('198.51.100.9 is still reserved');
        expect(html).toContain(EN['pub.relays.destroy.addr.retry']);
        // A working relay gets no button at all: its delete would take
        // the live server and everyone on it.
        const live = renderToStaticMarkup(<UnreleasedAddresses t={t} ips={['198.51.100.9']} />);
        expect(live).not.toContain(EN['pub.relays.destroy.addr.retry']);
        expect(live).toContain(EN['pub.relays.destroy.addr.earlier_try']);
    });

    it('Try again on a relay card never deletes a working relay, and keeps an unfinished one', async () => {
        const mk = () => ({
            relayDestroy: vi.fn(async (_op: number, _del: boolean) => report()),
            setupRemoveServer: vi.fn(async (_op: number) => report()),
        });
        const dead = mk();
        await retryRelease({ id: 1, status: 'decommissioned' }, dead);
        expect(dead.relayDestroy).toHaveBeenCalledWith(1, true);
        expect(dead.setupRemoveServer).not.toHaveBeenCalled();
        const unfinished = mk();
        await retryRelease({ id: 2, status: 'pre-provision' }, unfinished);
        expect(unfinished.setupRemoveServer).toHaveBeenCalledWith(2);
        expect(unfinished.relayDestroy).not.toHaveBeenCalled();
        const working = mk();
        // PA-1: a working relay's retry is a release of the address
        // alone, never a delete of any kind.
        expect(await retryRelease({ id: 3, status: 'provisioned' }, working)).toBeNull();
        expect(working.relayDestroy).not.toHaveBeenCalled();
        expect(working.setupRemoveServer).not.toHaveBeenCalled();
        expect(releaseRetryFor('provisioned')).toBe('release_address');
        expect(releaseRetryFor('rebuild_failed')).toBeNull();
        expect(listSource).toContain('releaseRetryFor(op.status)');
    });

    it('"billing has stopped" only when every address is released', () => {
        expect(stillBills(report())).toBe(false);
        expect(stillBills(report({ addresses: [addrs[0]] }))).toBe(false);
        expect(stillBills(report({ addresses: [addrs[0], addrs[2]] }))).toBe(true);
        expect(stillBills(report({ addresses: [{ id: '4', ip: '198.51.100.4', released: false, code: 'still_attached' }] }))).toBe(true);
        expect(listSource).toContain("t('pub.relays.destroy.addr.server_gone_address_left')");
        expect(listSource).toContain("t('pub.relays.destroy.addr.retry_ok_some_left')");
    });

    it('provider warnings are under Details only', () => {
        const i = listSource.indexOf('(report.warnings ?? []).length > 0');
        expect(listSource.slice(i, i + 200)).toContain('<WhatIsThis');
    });

    it('each address code has a sentence', () => {
        for (const c of ['released', 'not_daal', 'still_attached', 'release_failed'] as const) {
            expect(EN[addressLineKey(c)]).toContain('{ip}');
        }
    });
});

// ---------------------------------------------------------------- D5

describe('D5 one person as QR or text', () => {
    it('the QR sheet streams the artifact it is given, not a hard-coded everyone file', () => {
        expect(recipientArtifact(42)).toBe('recipient:42');
        expect(qrSource).toMatch(/Wizard\.qrRender\(\s*operatorId,\s*artifact,/);
        expect(qrSource).not.toMatch(/Wizard\.qrRender\(\s*operatorId,\s*'shared'/);
        expect(pageSource).toContain('artifact: recipientArtifact(r.id)');
        expect(pageSource).toContain('Wizard.copyPasteable(operatorId, recipientArtifact(r.id))');
    });

    it('a failed per-person QR does not send the publisher to the everyone-file button', () => {
        expect(qrErrorBody(t, 'shared', 'x')).toBe(EN['qr.send.error.body']);
        expect(qrErrorBody(t, 'recipient:4', 'E_FILE_MISSING: gone')).toBe(EN['pub.fail.file_missing']);
        expect(qrErrorBody(t, 'recipient:4', 'E_FILE_MISSING: gone')).not.toContain('Make the file');
    });

    it('the copy note says only that person can open it', () => {
        expect(EN['pub.person.copied']).toContain("Paste it into a message. Only {name}'s phone can open it.");
    });
});

// ------------------------------------------------- codes, copy, no commands

describe('error codes and copy', () => {
    it('the new error codes classify and have plain sentences', () => {
        const map: Record<string, string> = {
            E_SETUP_RUNNING: 'pub.fail.setup_running',
            E_SERVER_EXISTS: 'pub.fail.server_exists',
            E_NOT_SUPPORTED: 'pub.fail.not_supported',
            E_RELAY_UNREACHABLE: 'pub.fail.unreachable',
            E_FILE_MISSING: 'pub.fail.file_missing',
            E_DEPLOY_TOO_OLD: 'pub.fail.deploy_too_old',
        };
        for (const [code, key] of Object.entries(map)) {
            expect(classifyPublisherError(`${code}: tail`)).toBe(code);
            expect(failureKey(`${code}: tail`)).toBe(key);
            expect(EN[key]).toBeTruthy();
        }
    });

    const NEW_SOURCES = [
        recoverCardSource,
        accountSheetSource,
        renewSheetSource,
        healthPanelSource,
        addrSource,
    ];

    it('never renders an audit hint, and no new string carries a command line', () => {
        for (const s of NEW_SOURCES) {
            expect(s).not.toMatch(/\.hint\b/);
        }
        const newKeys = Object.keys(EN).filter((k) =>
            /^pub\.(setup|account|renew|health|person|relays\.destroy\.addr)\./.test(k),
        );
        expect(newKeys.length).toBeGreaterThan(150);
        for (const k of newKeys) {
            expect(EN[k], k).not.toMatch(/daal-deploy|--[a-z]|hcloud|vultr-cli|\bcurl\b|\bssh\b/i);
        }
        // The old command-line warning is not drawn in the main copy.
        expect(listSource).not.toMatch(/color: 'var\(--red\)' \}\}>\s*\{w\}/);
    });

    it('every key the new screens use, including computed ones, exists in English and Persian', () => {
        const keys = new Set<string>();
        for (const src of [...NEW_SOURCES, wizardSource, listSource, pageSource, rebuildSource]) {
            for (const m of src.matchAll(/t\(\s*'((?:pub)\.(?:setup|account|renew|health|person|relays\.destroy\.addr|relays\.interrupted|relays\.open|fail)[A-Za-z0-9_.]*)'/g)) {
                keys.add(m[1]);
            }
        }
        const computed: string[] = [];
        for (const s of STATES) {
            const v = recoveryView(recoveryFixture(s));
            computed.push(v.titleKey, ...v.bodyKeys, ...v.buttons.map(buttonKey));
        }
        computed.push(
            recoveryView(null).titleKey,
            recoveryView(recoveryFixture('server_running', { started_at_unix: 0 })).titleKey,
            ...recoveryView(recoveryFixture('server_running', { server_origin: 'yours' })).bodyKeys,
            ...recoveryView(recoveryFixture('server_running', { can_finish_here: false })).bodyKeys,
            ...[...DESTRUCTIVE].map(confirmKey),
            recoveryView(recoveryFixture('nothing_billing', { billing: 'yes' })).titleKey,
            ...recoveryView(recoveryFixture('nothing_billing', { billing: 'yes' })).bodyKeys,
            cancelBodyKey(recoveryFixture('nothing_billing', { billing: 'yes' })),
            'pub.renew.banner.missing',
            'pub.renew.banner.missing_one',
            'pub.renew.banner.everyone_missing',
            'pub.setup.recover.done',
            'pub.relays.destroy.addr.earlier_try',
            'pub.relays.destroy.addr.server_gone_address_left',
            'pub.relays.destroy.addr.retry_ok_some_left',
            ...[...DESTRUCTIVE].map(buttonKey),
            ...['server', 'floating-ip', 'ssh-key', 'firewall', 'x'].map(kindKey),
            ...['offline', 'token_rejected', 'unsupported_provider', 'custody_locked', 'failed'].map((c) =>
                errorKey(c as never),
            ),
            ...['billing_unused', 'unfinished', 'free_leftovers', 'cannot_tell', 'in_use'].map(
                (g) => `pub.account.group.${g}`,
            ),
            ...(['working', 'partly', 'not_working', 'unknown'] as RelayHealth['overall'][]).map(overallKey),
            ...(['running', 'starting', 'stopped', 'missing', 'error', 'not_checked'] as RelayHealth['server'][]).map(
                (s) => serverLineKey(s)!,
            ),
            ...(['answers', 'no_answer', 'refused', 'too_old', 'error', 'not_checked'] as RelayHealth['management'][]).map(
                (m) => managementLineKey(healthFixture({ management: m })),
            ),
            ...['answers', 'no_answer', 'wrong_server', 'not_testable_here'].map((w) => wayStateKey(w as never)),
            ...[
                'vless-reality',
                'websocket-tls',
                'naive',
                'anytls',
                'shadowsocks',
                'hysteria2',
                'tuic',
                'wireguard',
                'other',
            ].map(familyNameKey),
        );
        for (const k of computed) keys.add(k);
        expect(keys.size).toBeGreaterThan(120);
        for (const k of keys) {
            expect(EN[k], `en ${k}`).toBeTruthy();
            expect(FA[k], `fa ${k}`).toBeTruthy();
            expect(FA[k], `fa ${k} is still English`).not.toBe(EN[k]);
        }
    });
});

describe('D4: an address list the helper could not read', () => {
    const tt = (k: string) => (en as Record<string, string>)[k] ?? k;
    it('says the list could not be read instead of naming an empty address', () => {
        const line = addressLineText(tt, 'release_failed', '');
        expect(line).toBe((en as Record<string, string>)['pub.relays.destroy.addr.list_unreadable']);
        expect(line).not.toContain('{ip}');
        expect(addressLineText(tt, 'release_failed', '198.51.100.9')).toContain('198.51.100.9');
        const html = renderToStaticMarkup(<UnreleasedAddresses t={tt} ips={['']} onRetry={() => {}} />);
        expect(html).not.toMatch(/Address\s+is still/);
        expect(html).toContain('Try again');
        expect((fa as Record<string, string>)['pub.relays.destroy.addr.list_unreadable']).toBeTruthy();
    });
});
