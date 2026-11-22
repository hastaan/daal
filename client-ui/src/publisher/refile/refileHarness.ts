// refileHarness — the harness's fake shell answers for "New files for
// everyone" (harness/publisherFake.ts registers them in one line). Off
// unless the scenario passes `params: { refile: '1' }`, so every other
// publisher scenario keeps its own ledger and files.
//
// With it on, the working relay has a ready standby address whose code
// is in the plain form, no file for everyone, and `wizard_refile_people`
// answers a new file for each person not removed after a short wait.
// Made-up values only.
import type { RecipientSummary } from '../wizardCommands';

type Args = Record<string, unknown> | undefined;
type Table = Record<string, (a: Args) => unknown>;

export function refileFake(f: { params?: Record<string, string> }, base: Table): Table {
    if (f.params?.refile !== '1') return {};
    const op = (a: Args) => Number(a?.operatorId ?? (a?.input as { operator_id?: number })?.operator_id ?? 1);
    const now = Math.floor(Date.now() / 1000);
    const listArtifacts = base.wizard_list_artifacts;
    const listPeople = base.wizard_recipient_list;
    return {
        wizard_list_artifacts: (a) => {
            const all = (listArtifacts?.(a) ?? []) as Array<{ kind: string }>;
            return all.filter((x) => x.kind !== 'shared_sbp');
        },
        wizard_addons_list: (a) =>
            op(a) === 1
                ? [
                      {
                          id: 900,
                          operator_id: 1,
                          kind: 'standby',
                          state: 'ready',
                          provider_ids: {},
                          monthly_cost_cents: 300,
                          cost_currency: 'EUR',
                          has_secret: false,
                          detail: {},
                          created_at_unix: now - 86_400,
                          updated_at_unix: now - 86_400,
                      },
                  ]
                : [],
        wizard_addon_standby_key: () => ({ key: '000G40 R40M3 0E209 185WP 03H2G', form: 'plain' }),
        wizard_refile_people: async (a) => {
            await new Promise((r) => setTimeout(r, 600));
            const people = ((listPeople?.(a) ?? []) as RecipientSummary[]).filter((r) => r.revoked_at_unix === 0);
            return {
                operator_id: op(a),
                items: people.map((r) => ({
                    recipient_id: r.id,
                    name: r.name,
                    display_name: r.display_name,
                    status: 'done',
                    reason: '',
                    sbpx_path: r.sbpx_path || `/data/daal/relay-1/r${r.id}.sbpx`,
                    detail: '',
                })),
                removal_failed: [],
                all_done: true,
                code_wrapped: true,
            };
        },
    };
}
