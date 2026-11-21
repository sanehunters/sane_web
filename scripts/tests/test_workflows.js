#!/usr/bin/env node
// Runs each saved workflow under stub agents to catch runtime errors and check the survive/kill logic.
// It launches nothing and touches no target.   node scripts/tests/test_workflows.js
const fs = require('fs'), path = require('path')
const DIR = path.join(__dirname, '..', '..', '.claude', 'workflows')
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor

async function run(file, args, agentImpl) {
  const src = fs.readFileSync(path.join(DIR, file), 'utf8').replace(/^export const meta/m, 'const meta')
  const logs = []
  const helpers = {
    args,
    log: m => logs.push(m),
    phase: () => {},
    budget: { total: null, spent: () => 0, remaining: () => Infinity },
    agent: async (prompt, opts = {}) => agentImpl(prompt, opts),
    parallel: async thunks => Promise.all(thunks.map(t => Promise.resolve().then(t).catch(() => null))),
    pipeline: async (items, ...stages) => Promise.all(items.map(async (item, i) => {
      let v = item
      try { for (const s of stages) v = await s(v, item, i) } catch (e) { return null }
      return v
    })),
  }
  const fn = new AsyncFunction(...Object.keys(helpers), src)
  return { result: await fn(...Object.values(helpers)), logs }
}

const entry = (agent, label, extra = {}) => ({ agent, label, asset: 'app.demo.example', brief: `# Brief for ${agent}\n## Task\nx`, preamble: '# Brief', ...extra })
const cand = { present: true, item: 'BAC-001', claim: 'A reads B', steps: '1. x', request: 'GET /x', response_fragment: '{}', evidence_path: '/e' }
let fail = 0
const check = (name, ok) => { if (!ok) fail++; console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}`) }

;(async () => {
  // squad-hunt: one lane finds a candidate that survives, one finds one that the guard refutes twice, one finds nothing, one agent dies
  let r = await run('squad-hunt.js', {
    engagement: 'demo', later: [],
    map: [entry('surface-mapper', 'map:app')],
    wave: [entry('class-hunter', 'authz:app', { lane: 'authz' }), entry('class-hunter', 'client:app', { lane: 'client' }),
           entry('class-hunter', 'infra:app', { lane: 'infra' }), entry('cve-exploiter', 'known:app', { lane: 'known' })],
  }, async (prompt, o) => {
    if (o.agentType === 'surface-mapper') return { map_path: '/m', facts_set: [], facts_unknown: [], promising_features: [], blockers: [] }
    if (o.label === 'authz:app') return { cards: [], candidate: cand, facts_changed: [], observations: [], stopped_because: 'candidate found' }
    if (o.label === 'client:app') return { cards: [], candidate: { ...cand, item: 'XSS-002' }, facts_changed: [], observations: [], stopped_because: 'candidate found' }
    if (o.label === 'infra:app') return { cards: [{ item: 'INF-001', outcome: 'negative', note: 'n' }], candidate: { present: false }, facts_changed: [], observations: [], stopped_because: 'queue finished' }
    if (o.label === 'known:app') return null
    if (o.label.endsWith('BAC-001')) return { verdict: o.agentType === 'verify-triager' ? 'weak' : 'holds', note: 'n' }
    if (o.label.endsWith('XSS-002')) return { verdict: o.agentType === 'verify-reproduce' ? 'holds' : 'refuted', note: 'n' }
    return null
  })
  check('squad-hunt returns one survivor (2 holds, triager weak)', r.result.survivors.length === 1 && r.result.survivors[0].candidate.item === 'BAC-001')
  check('squad-hunt kills the refuted candidate', r.result.killed.length === 1 && r.result.killed[0].item === 'XSS-002')
  check('squad-hunt reports the agent that died', r.result.failed.length === 1 && r.result.failed[0] === 'known:app')
  check('squad-hunt keeps the map result', r.result.maps.length === 1)

  // verify-finding: triager refutes -> does not survive even with two holds
  const lenses = ['verify-reproduce', 'verify-guard', 'verify-triager'].map(a => entry(a, `${a}:F-001`))
  r = await run('verify-finding.js', { finding: 'F-001', title: 't', asset: 'a', lenses }, async (p, o) => ({ verdict: o.agentType === 'verify-triager' ? 'refuted' : 'holds', note: 'n' }))
  check('verify-finding: triager refuted blocks survival', r.result.survives === false && Object.keys(r.result.verify_json.lenses).length === 3)
  r = await run('verify-finding.js', { finding: 'F-001', title: 't', asset: 'a', lenses }, async (p, o) => ({ verdict: o.agentType === 'verify-guard' ? 'weak' : 'holds', note: 'n' }))
  check('verify-finding: two holds and a weak guard survive', r.result.survives === true)
  r = await run('verify-finding.js', { finding: 'F-001', title: 't', asset: 'a', lenses }, async (p, o) => (o.agentType === 'verify-guard' ? null : { verdict: 'holds', note: 'n' }))
  check('verify-finding: a missing lens is not a pass', r.result.survives === false)

  // research-lenses: two lenses, then ranking
  r = await run('research-lenses.js', { asset: 'app.demo.example', lenses: [entry('researcher', 'research:second-path', { lens: 'second-path' }), entry('researcher', 'research:variant', { lens: 'variant' })] },
    async (p, o) => o.agentType === 'researcher'
      ? { hypotheses: [{ id: 'H-00' + (o.label.endsWith('variant') ? 2 : 1), claim: 'c', why: 'w', test: 't', tested: false, result: 'untested' }], new_card: '', notes: '' }
      : { ranked: [{ id: 'H-001', lens: 'second-path', claim: 'c', impact_if_true: 'i', plausibility: 'high', cost: 'low', reason: 'r' }], confirmed: [], gaps: ['billing'] })
  check('research-lenses merges both lenses and ranks', r.result.hypotheses.length === 2 && r.result.ranked.length === 1 && r.result.gaps[0] === 'billing')

  // cve-sweep: one verified, one clean
  r = await run('cve-sweep.js', { engagement: 'demo', products: [entry('cve-exploiter', 'cve:a'), entry('cve-exploiter', 'cve:b')] }, async (p, o) => {
    if (o.label === 'cve:a') return { products: [], cves: [{ id: 'CVE-2021-41773', status: 'verified', note: 'n' }], candidate: { ...cand, cve: 'CVE-2021-41773', item: 'CVE-004' }, urgent: 'KEV-listed RCE' }
    if (o.label === 'cve:b') return { products: [], cves: [], candidate: { present: false }, urgent: '' }
    return { verdict: 'holds', note: 'n' }
  })
  check('cve-sweep verifies the hit and relays the urgent note', r.result.survivors.length === 1 && r.logs.some(l => l.startsWith('URGENT')))

  console.log(fail ? `workflows: ${fail} check(s) failed` : 'workflows: all checks passed')
  process.exit(fail ? 1 : 0)
})().catch(e => { console.error(e); process.exit(1) })
