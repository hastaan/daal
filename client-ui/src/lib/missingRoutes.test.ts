// Backlog PH-26: after the store was reset the shell kept asking for
// the summary of a route that no longer existed, every two seconds.
import { describe, expect, it } from 'vitest';
import { MissingRoutes, RETRY_MS } from './missingRoutes';

describe('MissingRoutes', () => {
    it('asks for everything until told otherwise', () => {
        expect(new MissingRoutes().shouldAsk('r1', 0)).toBe(true);
    });
    it('gone: the list answered without the route — not asked again, however long', () => {
        const m = new MissingRoutes();
        m.failed('r9', 1000, ['r1', 'r2']);
        expect(m.shouldAsk('r9', 1001)).toBe(false);
        expect(m.shouldAsk('r9', 1000 + 100 * RETRY_MS)).toBe(false);
        expect(m.shouldAsk('r1', 1001)).toBe(true);
    });
    it('unreadable: the list did not answer, or still holds the route — asked again after a while', () => {
        for (const listed of [undefined, ['r9']]) {
            const m = new MissingRoutes();
            m.failed('r9', 1000, listed);
            expect(m.shouldAsk('r9', 1000 + RETRY_MS - 1)).toBe(false);
            expect(m.shouldAsk('r9', 1000 + RETRY_MS)).toBe(true);
        }
    });
    it('a list that shows the route, a successful read, or a changed route set clears it', () => {
        const m = new MissingRoutes();
        m.failed('a', 0, []);
        m.failed('b', 0, []);
        m.failed('c', 0, []);
        m.listed(['a']);
        m.found('b');
        expect(m.shouldAsk('a', 1)).toBe(true);
        expect(m.shouldAsk('b', 1)).toBe(true);
        expect(m.shouldAsk('c', 1)).toBe(false);
        m.clear();
        expect(m.shouldAsk('c', 1)).toBe(true);
    });
});
