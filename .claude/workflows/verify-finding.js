export const meta = {
  name: 'verify-finding',
  description: 'Three independent verification lenses on one finding: reproduce, find the guard, read as the triager',
  whenToUse: 'A finding folder exists with claim.md and evidence. Pass the JSON printed by `scripts/sane squad --mode verify --finding F-NNN --json` as args.',
  phases: [
    { title: 'Verify', detail: 'verify-reproduce, verify-guard and verify-triager in parallel, none sees the others or the hunter\'s reasoning' },
  ],
}

// args: { engagement, finding, title, asset, lenses: [{agent,label,brief}] }
const v = args
if (!v || !Array.isArray(v.lenses) || v.lenses.length !== 3) {
  throw new Error('Pass the JSON printed by `scripts/sane squad --mode verify --finding F-NNN --json` as the workflow args.')
}

const LENS_SCHEMA = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['holds', 'weak', 'refuted'] },
    note: { type: 'string', description: 'what was done and seen, checkable by a stranger' },
    reproductions: { type: 'integer', description: 'reproduce lens: clean reproductions achieved' },
    weakest_attacker: { type: 'string', description: 'reproduce lens: the weakest attacker position that still works' },
    explanations_tested: { type: 'array', items: { type: 'string' }, description: 'guard lens: each innocent explanation and its result' },
    cvss: { type: 'string', description: 'triager lens: the CVSS vector and score the evidence supports' },
    duplicate_risk: { type: 'string', description: 'triager lens: closest disclosed reports and judgement' },
    question: { type: 'string', description: 'triager lens: what a triager would ask back' },
  },
  required: ['verdict', 'note'],
}

phase('Verify')
const got = (await parallel(v.lenses.map(l => () =>
  agent(l.brief, { label: l.label, phase: 'Verify', agentType: l.agent, schema: LENS_SCHEMA })
    .then(r => (r ? { lens: l.agent, ...r } : null))))).filter(Boolean)

const holds = got.filter(x => x.verdict === 'holds').length
const tri = got.find(x => x.lens === 'verify-triager')
const complete = got.length === 3
const survives = complete && holds >= 2 && !(tri && tri.verdict === 'refuted')
if (!complete) log(`only ${got.length} of 3 lenses returned: the finding is not verified until all three have`)

const key = { 'verify-reproduce': 'reproduce', 'verify-guard': 'guard', 'verify-triager': 'triager' }
const verifyJson = { lenses: {} }
for (const x of got) verifyJson.lenses[key[x.lens]] = { verdict: x.verdict, note: x.note }

return {
  finding: v.finding,
  title: v.title,
  asset: v.asset,
  verdicts: got,
  survives,
  needs_chain: !!(tri && tri.verdict === 'weak'),
  verify_json: verifyJson,
  next_steps: survives
    ? `Write verify_json to findings/${v.finding}/verify.json; scripts/sane finding set ${v.finding} state=verified reproductions=<n>; scripts/sane mark <asset> <item> finding --finding ${v.finding}; then /chain if the triager said weak, else /report.`
    : `Write verify_json to findings/${v.finding}/verify.json; re-mark the item negative or parked with the reason the refuting lens gave. Delete nothing.`,
}
