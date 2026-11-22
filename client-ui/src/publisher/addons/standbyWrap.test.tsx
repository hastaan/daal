// The wrapped standby code (specs/update-ladder-v2.md §3) on screen: the
// publisher's code sheet says a wrapped code is useless without the
// person's own file, so it may go by SMS, a call or a messenger; a plain
// code keeps the earlier wording. The recipient's code field says a code
// works only with the file they already have, and sends either form to
// the engine unchanged.
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { byAttr } from "../../test/miniDom";
import type { FakeNode } from "../../test/miniDom";
import { createRig } from "../../test/rig";
import type { Rig } from "../../test/rig";
import type { AddonRow } from "./addonTypes";
import type { AccountsState } from "./accounts";

type Handler = (args: Record<string, unknown> | undefined) => unknown;
let handlers: Record<string, Handler> = {};

vi.mock("@tauri-apps/api/core", () => ({
  invoke: async (cmd: string, args?: Record<string, unknown>) => {
    const h = handlers[cmd];
    if (!h) throw `E_NOT_BUILT: ${cmd} is not mocked`;
    return h(args);
  },
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
}));

let rig: Rig;
beforeAll(() => {
  rig = createRig();
  const kept = new Map<string, string>();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => kept.get(k) ?? null,
      setItem: (k: string, v: string) => void kept.set(k, String(v)),
      removeItem: (k: string) => void kept.delete(k),
    },
  });
});
let ledger: AddonRow[] = [];
beforeEach(() => {
  handlers = { wizard_addons_list: () => ledger };
  ledger = [];
});
afterEach(async () => {
  await rig.unmountAll();
});

const { translate } = await import("../../lib/i18n");
const { AddonsSection } = await import("./AddonsSection");
const { StandbyCodeEntry } = await import("../../components/StandbyCodeEntry");
const en = (k: string) => translate("en", k);
const fa = (k: string) => translate("fa", k);
const tid = (root: FakeNode, id: string) => byAttr(root, "data-testid", id);
const btn = (root: FakeNode, id: string) => byAttr(root, "data-button", id);

const NONE: AccountsState = {
  hetzner: true,
  hetznerAccount: true,
  cloudflare: { connected: false, zone: "" },
  google: { connected: false, scriptMade: false, signIn: false },
};
const PLAIN = "000G40 R40M3 0E209 185WP 03H2G";
const WRAPPED = "DW08XN Z6SE1 KJD95 57SAY MT9M8";

function row(state: AddonRow["state"]): AddonRow {
  return {
    id: 7,
    operator_id: 1,
    kind: "standby",
    state,
    provider_ids: {},
    monthly_cost_cents: 300,
    cost_currency: "EUR",
    has_secret: false,
    detail: { mode: "sealed" },
    created_at_unix: 1,
    updated_at_unix: 1,
  };
}

const sheetNote = (m: { container: FakeNode }) =>
  byAttr(
    tid(m.container, "standby-code-sheet") as FakeNode,
    "data-form",
    "wrapped",
  ) ??
  byAttr(
    tid(m.container, "standby-code-sheet") as FakeNode,
    "data-form",
    "plain",
  );

describe("the publisher sees which code it is sending", () => {
  it("a wrapped code: one line says it is useless without the person’s file", async () => {
    ledger = [row("ready")];
    handlers.wizard_addon_standby_key = () => ({
      key: WRAPPED,
      form: "wrapped",
    });
    const m = await rig.mount(
      <AddonsSection t={en} operatorId={1} accounts={NONE} />,
    );
    await rig.click(btn(m.container, "standby-show-key"));
    expect(tid(m.container, "standby-key")?.textContent).toBe(WRAPPED);
    const note = sheetNote(m);
    expect(note?.getAttribute("data-form")).toBe("wrapped");
    expect(note?.textContent).toBe(en("standby.wrap.body"));
    expect(en("standby.wrap.body")).toMatch(/SMS/);
  });

  it("beside a wrapped code, one quiet action shows the plain code with its caution", async () => {
    ledger = [row("ready")];
    handlers.wizard_addon_standby_key = () => ({
      key: WRAPPED,
      form: "wrapped",
      plain_key: PLAIN,
    });
    const m = await rig.mount(
      <AddonsSection t={en} operatorId={1} accounts={NONE} />,
    );
    await rig.click(btn(m.container, "standby-show-key"));
    const fallback = btn(m.container, "standby-key-plain");
    expect(fallback?.textContent).toContain(en("standby.wrap.fallback"));
    await rig.click(fallback);
    expect(tid(m.container, "standby-key")?.textContent).toBe(PLAIN);
    const note = sheetNote(m);
    expect(note?.getAttribute("data-form")).toBe("plain");
    expect(note?.textContent).toBe(en("pub.addons.standby.key.body"));
    expect(btn(m.container, "standby-key-plain")).toBeNull();
  });

  it("a plain code (an Everyone file, or an older app): the earlier wording", async () => {
    ledger = [row("ready")];
    handlers.wizard_addon_standby_key = () => ({ key: PLAIN });
    const m = await rig.mount(
      <AddonsSection t={en} operatorId={1} accounts={NONE} />,
    );
    await rig.click(btn(m.container, "standby-show-key"));
    const note = sheetNote(m);
    expect(note?.getAttribute("data-form")).toBe("plain");
    expect(note?.textContent).toBe(en("pub.addons.standby.key.body"));
    expect(m.container.textContent).not.toContain(en("standby.wrap.body"));
  });

  it("a switch shows the form the helper sent", async () => {
    ledger = [row("ready")];
    handlers.wizard_addon_standby_promote = () => ({
      addon: row("promoted"),
      key: WRAPPED,
      key_form: "wrapped",
      refresh_note_published: true,
      warnings: [],
    });
    const m = await rig.mount(
      <AddonsSection t={en} operatorId={1} accounts={NONE} />,
    );
    await rig.click(btn(m.container, "standby-switch"));
    ledger = [row("promoted")];
    await rig.click(btn(m.container, "confirm-yes"));
    expect(tid(m.container, "standby-key")?.textContent).toBe(WRAPPED);
    expect(sheetNote(m)?.getAttribute("data-form")).toBe("wrapped");
  });
});

describe("the recipient types either form", () => {
  it("one line says the code needs their file; the code goes to the engine as typed", async () => {
    const typed: string[] = [];
    const m = await rig.mount(
      <StandbyCodeEntry
        t={en}
        enter={async (k) => {
          typed.push(k);
          return "accepted";
        }}
      />,
    );
    expect(tid(m.container, "standby-code-file-note")?.textContent).toBe(
      en("standby.wrap.entry_note"),
    );
    await rig.type(
      btn(m.container, "standby-code-input"),
      "dw08xn-z6se1 kjd95 57say mt9m8",
    );
    await rig.click(btn(m.container, "standby-code-go"));
    expect(typed).toEqual([WRAPPED]);
  });

  it("both lines exist in Persian, without narrated gestures", () => {
    for (const k of ["standby.wrap.body", "standby.wrap.entry_note", "standby.wrap.fallback"]) {
      expect(fa(k)).not.toBe(k);
      expect(fa(k)).not.toBe(en(k));
      expect(fa(k)).not.toContain("بزنید");
    }
  });
});
