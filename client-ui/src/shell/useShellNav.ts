// useShellNav — the one navigation model all three shells share.
//
// Four places: Connection, Files ('network'), Publisher (only when it is
// switched on) and Settings. Status is not a place of its own: it is an
// inner page of Settings, so `navigate('status')` (Home's overflow, the
// desktop title bar) opens Settings → Status everywhere (spec C8, C9).
// Picking the Settings tab or sidebar item always shows its list.

import { useCallback, useEffect, useState } from 'react';
import { Prefs } from '../lib/prefs';
import type { SectionId } from './Sidebar';
import type { SettingsSubPage } from '../d2pages/SettingsPage';
import { harnessStart } from './harnessStart';
import { openedFileWaiting, startOpenedFile, watchUnclaimedOpenedFiles } from '../recipient/openedFile';

export type ShellSection = 'connection' | 'network' | 'publisher' | 'settings';

/** The places in the order every shell shows them. */
export function visibleSections(publisherEnabled: boolean): ShellSection[] {
    return publisherEnabled
        ? ['connection', 'network', 'publisher', 'settings']
        : ['connection', 'network', 'settings'];
}

export function useShellNav(publisherEnabled: boolean) {
    const [start] = useState(harnessStart);
    const [section, setSection] = useState<ShellSection>(() => {
        if (start) return start.section;
        const first = Prefs.takeFirstSection();
        return first ?? 'connection';
    });
    const [settingsPage, setSettingsPage] = useState<SettingsSubPage>(start?.settingsPage ?? 'main');
    const [eraseOpen, setEraseOpen] = useState<boolean>(start?.erase ?? false);

    /** Go to a place by the pages' own vocabulary (SectionId). */
    const navigate = useCallback(
        (target: SectionId) => {
            if (target === 'status') {
                setSection('settings');
                setSettingsPage('status');
                return;
            }
            if (target === 'publisher' && !publisherEnabled) return;
            setSection(target);
        },
        [publisherEnabled],
    );

    /** A tab or sidebar tap. Settings always opens on its list: only
     *  navigate('status') lands on an inner page. */
    const pick = useCallback(
        (target: ShellSection) => {
            if (target === 'publisher' && !publisherEnabled) return;
            if (target === 'settings') setSettingsPage('main');
            setSection(target);
        },
        [publisherEnabled],
    );

    // A file handed to Daal by Android ("Open with Daal", "Share to
    // Daal") is opened by Home or Files (recipient/openedFile.ts holds it
    // until one of them is up). Listening starts here, at mount, so the
    // native side learns the page listens whatever place shows first.
    //   On launch: go to Home, where it opens (nothing is in progress yet).
    //   While Daal runs, from Publisher or Settings: never pull the person
    //   away (a relay being built, recovery words on screen, a restore,
    //   an erase confirm): say a file is waiting, with "Open".
    // An older shell has neither the command nor the event: nothing happens.
    const [fileWaiting, setFileWaiting] = useState(false);
    useEffect(() => {
        startOpenedFile();
        return watchUnclaimedOpenedFiles((source) => {
            if (source === 'launch') {
                setSection((s) => (s === 'connection' || s === 'network' ? s : 'connection'));
            } else {
                setFileWaiting(true);
            }
        });
    }, []);
    // Home or Files took it on mount.
    useEffect(() => {
        if (section === 'connection' || section === 'network') setFileWaiting(false);
    }, [section]);
    const openWaitingFile = useCallback(() => {
        setFileWaiting(false);
        setSection('connection');
    }, []);
    const dismissFileWaiting = useCallback(() => setFileWaiting(false), []);

    // A section that is switched off is never shown.
    const shown: ShellSection = section === 'publisher' && !publisherEnabled ? 'connection' : section;

    return {
        section: shown,
        setSection,
        settingsPage,
        setSettingsPage,
        navigate,
        pick,
        eraseOpen,
        setEraseOpen,
        /** A handed-over file waits while the person is elsewhere. */
        fileWaiting: fileWaiting && openedFileWaiting(),
        openWaitingFile,
        dismissFileWaiting,
    };
}
