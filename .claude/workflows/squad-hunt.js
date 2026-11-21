export const meta = {
  name: 'squad-hunt',
  description: 'One wave of the hunt: mappers and lane hunters side by side per deployment, then three independent verification lenses on every candidate',
  whenToUse: 'Several lanes or deployments have queued cards. Pass the JSON printed by `scripts/sane squad --json` as args.',
  phases: [
    { title: 'Map', detail: 'one surface-mapper per deployment that has no map yet' },
    { title: 'Hunt', detail: 'one agent per deployment and lane, each with its own brief and rate share' },
    { title: 'Verify', detail: 'reproduce, find-the-guard and triager lenses on every candidate' },
  ],
}

// args: { engagement, map: [{agent,label,asset,brief,preamble}], wave: [{agent,label,asset,lane,brief,preamble}], later: [...] }
const plan = args
if (!plan || !Array.isArray(plan.wave) || !Array.isArray(plan.map)) {
  throw new Error('Pass the JSON printed by `scripts/sane squad --json` as the workflow args (an object, not a string).')
}

const MAP_SCHEMA = {
  type: 'object',
  properties: {
    map_path: { type: 'string' },
    facts_set: { type: 'array', items: { type: 'string' } },
    facts_unknown: { type: 'array', items: { type: 'string' } },
    promising_features: { type: 'array', items: { type: 'string' } },
    blockers: { type: 'array', items: { type: 'string' } },
  },
  required: ['map_path', 'facts_set', 'facts_unknown', 'promising_features', 'blockers'],
}
const HUNT_SCHEMA = {
  type: 'object',
  properties: {
    cards: {
      type: 'array',
      items: {
        type: 'object',
        properties: { item: { type: 'string' }, outcome: { type: 'string' }, note: { type: 'string' } },
        required: ['item', 'outcome', 'note'],
      },
    },
    candidate: {
      type: 'object',
      properties: {
        present: { type: 'boolean' },
        item: { type: 'string' },
        claim: { type: 'string', description: 'one sentence: attacker starting position, action, result' },
        steps: { type: 'string', description: 'numbered reproduction steps exactly as performed' },
        request: { type: 'string', description: 'the raw request that shows it, secrets redacted' },
        response_fragment: { type: 'string' },
        evidence_path: { type: 'string' },
      },
      required: ['present'],
    },
    facts_changed: { type: 'array', items: { type: 'string' } },
    observations: { type: 'array', items: { type: 'string' } },
    stopped_because: { type: 'string', description: 'queue finished | candidate found | timebox | incident (say which) | blocked (say on what)' },
  },
  required: ['cards', 'candidate', 'facts_changed', 'observations', 'stopped_because'],
}
const LENS_SCHEMA = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['holds', 'weak', 'refuted'] },
    note: { type: 'string' },
    cvss: { type: 'string', description: 'triager lens only: the CVSS vector the evidence supports' },
    duplicate_risk: { type: 'string', description: 'triager lens only: closest disclosed reports and judgement' },
  },
  required: ['verdict', 'note'],
}

const LENSES = [
  ['verify-reproduce', 'Reproduce it independently. Build clean state (new sessions for the test accounts, fresh test objects), follow the steps below literally, twice. Then weaken the attacker (unauthenticated, lowest role, another tenant) and record which positions still work. If the steps as written fail and a variation works, the verdict is weak and you report the variation.'],
  ['verify-guard', 'Try to kill it. Assume the application is correct and test every innocent explanation with a request: the object is public or shared with the attacker; the data returned is the attacker\'s own, a default or a placeholder; it is a cache; the attacker had a legitimate precondition; the two accounts share state; a later check stops the real impact; the response is an error that resembles success; it is documented behaviour.'],
  ['verify-triager', 'Read it as the programme\'s triager. Send nothing to the target. Check scope (`scripts/sane scope check`), the policy\'s exclusions, intended behaviour, the impact as actually proven, preconditions, the CVSS 3.1 vector the evidence supports, and duplicates among disclosed reports (`scripts/sane kb program`, `scripts/sane kb search`).'],
]

function verifyPrompt(entry, cand, lens, task) {
  return `${entry.preamble}

## Task — verification lens: ${lens}
${task}

No finding folder exists yet for this candidate. The claim and its evidence are below; this is everything you get, and you should not look for the hunter's reasoning. Save any captures you make under \`${cand.evidence_path || 'the evidence path below'}/${lens}/\`.

## The candidate (checklist item ${cand.item || 'unknown'})
Claim: ${cand.claim || '(not stated)'}

Steps as the hunter performed them:
${cand.steps || '(not given)'}

Request:
\`\`\`
${cand.request || '(not given)'}
\`\`\`

Response fragment:
\`\`\`
${cand.response_fragment || '(not given)'}
\`\`\`

Evidence on disk: ${cand.evidence_path || '(not given)'}

## Return
verdict: holds | weak | refuted, with a note a stranger could check.`
}

log(`${plan.map.length} deployment(s) to map, ${plan.wave.length} lane agent(s) to run, ${(plan.later || []).length} lane(s) waiting for a later wave`)

const maps = parallel(plan.map.map(m => () =>
  agent(m.brief, { label: m.label, phase: 'Map', agentType: 'surface-mapper', schema: MAP_SCHEMA })
    .then(r => ({ label: m.label, asset: m.asset, result: r }))))

const lanes = pipeline(
  plan.wave,
  e => agent(e.brief, { label: e.label, phase: 'Hunt', agentType: e.agent, schema: HUNT_SCHEMA }),
  (h, e) => {
    if (!h) return { label: e.label, asset: e.asset, lane: e.lane, failed: true }
    const c = h.candidate
    if (!c || !c.present) return { label: e.label, asset: e.asset, lane: e.lane, hunt: h, verdicts: null, survives: false }
    return parallel(LENSES.map(([lens, task]) => () =>
      agent(verifyPrompt(e, c, lens, task), { label: `${lens}:${c.item || e.label}`, phase: 'Verify', agentType: lens, schema: LENS_SCHEMA })
        .then(v => ({ lens, ...v }))))
      .then(vs => {
        const got = vs.filter(Boolean)
        const holds = got.filter(v => v.verdict === 'holds').length
        const tri = got.find(v => v.lens === 'verify-triager')
        const survives = got.length === 3 && holds >= 2 && !(tri && tri.verdict === 'refuted')
        return { label: e.label, asset: e.asset, lane: e.lane, hunt: h, verdicts: got, survives }
      })
  },
)

const [mapResults, laneResults] = await Promise.all([maps, lanes])
const results = laneResults.map((r, i) => r || { label: plan.wave[i].label, failed: true })
const failed = results.filter(r => r.failed).map(r => r.label)
const survivors = results.filter(r => r.survives)
const killed = results.filter(r => r.hunt && r.hunt.candidate && r.hunt.candidate.present && !r.survives)
if (failed.length) log(`agents that did not finish (re-run their lane): ${failed.join(', ')}`)
log(`${survivors.length} candidate(s) survived verification, ${killed.length} did not`)

return {
  engagement: plan.engagement,
  maps: mapResults.filter(Boolean),
  lanes: results,
  survivors: survivors.map(r => ({ label: r.label, asset: r.asset, lane: r.lane, candidate: r.hunt.candidate, verdicts: r.verdicts })),
  killed: killed.map(r => ({ label: r.label, item: r.hunt.candidate.item, verdicts: r.verdicts })),
  failed,
  later: plan.later || [],
  next_steps: 'For each survivor: scripts/sane finding new, write claim.md and verify.json from the verdicts, scripts/sane mark ... finding, then /chain or /report. For each killed candidate: re-mark the item negative or parked with the lens\'s reason. Then scripts/sane squad again for the next wave.',
}
