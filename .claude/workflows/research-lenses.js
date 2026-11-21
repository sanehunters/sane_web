export const meta = {
  name: 'research-lenses',
  description: 'Novel-bug research on one deployment: one researcher per lens in parallel, then a cross-lens ranking of every hypothesis',
  whenToUse: 'The card queue is thin or the deployment is rich, and PB-04 is done for it. Pass the JSON printed by `scripts/sane squad --mode research <host> --json` as args.',
  phases: [
    { title: 'Research', detail: 'one researcher per lens, each reading the map and code and recording hypotheses in the ledger' },
    { title: 'Rank', detail: 'deduplicate across lenses and rank by impact, plausibility and cost of the decisive experiment' },
  ],
}

// args: { engagement, asset, lenses: [{agent,label,lens,brief,preamble}] }
const r = args
if (!r || !Array.isArray(r.lenses) || !r.lenses.length) {
  throw new Error('Pass the JSON printed by `scripts/sane squad --mode research <host> --json` as the workflow args.')
}

const HYP_SCHEMA = {
  type: 'object',
  properties: {
    hypotheses: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'the H-NNN id returned by `scripts/sane hyp add`' },
          claim: { type: 'string' },
          why: { type: 'string', description: 'the concrete observation that makes it plausible' },
          test: { type: 'string', description: 'the cheapest decisive experiment, with its control' },
          tested: { type: 'boolean' },
          result: { type: 'string', description: 'confirmed | refuted | parked | untested, with what was seen' },
          evidence_path: { type: 'string' },
        },
        required: ['id', 'claim', 'why', 'test', 'tested', 'result'],
      },
    },
    new_card: { type: 'string', description: 'a pattern that deserves a checklist card, or empty' },
    notes: { type: 'string' },
  },
  required: ['hypotheses', 'new_card', 'notes'],
}
const RANK_SCHEMA = {
  type: 'object',
  properties: {
    ranked: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          lens: { type: 'string' },
          claim: { type: 'string' },
          impact_if_true: { type: 'string' },
          plausibility: { type: 'string', enum: ['high', 'medium', 'low'] },
          cost: { type: 'string', enum: ['low', 'medium', 'high'] },
          merged_with: { type: 'array', items: { type: 'string' } },
          reason: { type: 'string' },
        },
        required: ['id', 'lens', 'claim', 'impact_if_true', 'plausibility', 'cost', 'reason'],
      },
    },
    confirmed: { type: 'array', items: { type: 'string' }, description: 'ids already confirmed by a researcher: these go to verification now' },
    gaps: { type: 'array', items: { type: 'string' }, description: 'features or invariants no lens examined' },
  },
  required: ['ranked', 'confirmed', 'gaps'],
}

phase('Research')
// barrier on purpose: ranking needs every lens's hypotheses together
const found = (await parallel(r.lenses.map(l => () =>
  agent(l.brief, { label: l.label, phase: 'Research', agentType: 'researcher', schema: HYP_SCHEMA })
    .then(x => (x ? { lens: l.lens, ...x } : null))))).filter(Boolean)

const missing = r.lenses.length - found.length
if (missing) log(`${missing} lens(es) did not return: re-run them before treating the ledger as complete`)
const all = found.flatMap(f => f.hypotheses.map(h => ({ lens: f.lens, ...h })))
log(`${all.length} hypotheses from ${found.length} lenses`)
if (!all.length) return { asset: r.asset, hypotheses: [], ranked: [], confirmed: [], gaps: [], new_cards: [] }

phase('Rank')
const rank = await agent(`${r.lenses[0].preamble}

## Task — rank the research ledger for \`${r.asset}\`
${found.length} researchers each applied one lens to this deployment and recorded hypotheses about invariants the application may not enforce. You send nothing to the target. Read \`$E/recon/${r.asset}/map.md\` (the feature table and trust model) so you can judge them, then:

1. Merge duplicates: the same underlying break seen through two lenses is one hypothesis (keep the better-evidenced id, list the others in merged_with).
2. Rank what remains by (impact if true) x (how plausible the concrete observation makes it) / (cost of the decisive experiment). A hypothesis with no concrete observation behind it ranks last however exciting it sounds.
3. List the ids a researcher already confirmed: those go to three-lens verification, not back into the queue.
4. Name the gaps: features in the map, or invariants, that no hypothesis touches.

## The hypotheses
${JSON.stringify(all, null, 1)}`, { label: `rank:${r.asset}`, phase: 'Rank', schema: RANK_SCHEMA })

return {
  asset: r.asset,
  hypotheses: all,
  ranked: rank ? rank.ranked : [],
  confirmed: rank ? rank.confirmed : all.filter(h => /^confirmed/i.test(h.result)).map(h => h.id),
  gaps: rank ? rank.gaps : [],
  new_cards: found.map(f => f.new_card).filter(Boolean),
  next_steps: 'Confirmed ids: scripts/sane finding new, then /verify. Ranked, untested: run the decisive experiment for the top five, 45 minutes each, and close every one with scripts/sane hyp close. Gaps: a second research pass with the lens that fits.',
}
