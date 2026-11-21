# FLOW — the hunt, drawn

Four diagrams: the whole flow, how one asset × test pair is decided, the CVE path, and the research loop. GitHub
renders them; each node names the playbook or command behind it.

## 1. The whole flow

```mermaid
flowchart TD
    OP([Operator names a programme]) --> PB00["PB-00 Engage<br/>authorisation · policy · rules · exclusions"]
    PB00 -->|no written basis| STOP1([Stop: ask the operator])
    PB00 --> PB01["PB-01 Scope<br/>import from HackerOne · lock · prove with 3 checks"]
    PB01 --> PB02["PB-02 Recon<br/>passive subdomains · ranges · ports<br/>scope-filtered before anything is touched"]
    PB02 --> PB03["PB-03 Fingerprint<br/>~20 requests per host<br/>tier · technology · clusters · auto-facts"]

    PB03 -->|product with a version| PB07["PB-07 CVE<br/>pin version → look up → verify → minimal exploit"]
    PB03 -->|tier app or api| PB04["PB-04 Map<br/>accounts A and B · walk every feature<br/>settle the facts · trust model"]
    PB03 -->|tier dead / default / static| PB05

    PB04 --> PB05["PB-05 Plan<br/>facts × Requires → todo · probe · n/a · blocked · excluded"]
    PB05 -->|unknown facts| PB04
    PB05 -->|queue| PB06["PB-06 Hunt<br/>one card · one clock · one outcome"]
    PB05 -->|queue empty or thin| PB08["PB-08 Research<br/>invariants → hypotheses → experiments"]

    PB06 -->|negative: mechanism noted| PB06
    PB06 -->|primitive without impact| PARK[(parked)]
    PB06 -->|signal| PB09
    PB07 -->|check verified| PB09
    PB08 -->|hypothesis confirmed| PB09
    PB08 -->|new surface| PB05

    PB09{"PB-09 Verify<br/>reproduce · find the guard · read as triager"}
    PB09 -->|refuted| PB06
    PB09 -->|real but weak| PB10["PB-10 Chain<br/>what is the primitive missing?"]
    PB09 -->|holds| PB11
    PARK --> PB10
    PB10 -->|impact demonstrated| PB09
    PB10 -->|no second link in 90 min| PARK

    PB11["PB-11 Report<br/>rebuild proof · write · sane gate"] -->|gate fails| PB11
    PB11 -->|READY| HAND([Operator submits on HackerOne])
    HAND --> PB12["PB-12 After submission<br/>replies · retest · bypass of the fix · lessons"]
    PB12 --> PB06

    SIG["PB-13 Signals<br/>any observation → record a fact → re-plan"] -.-> PB05
    INC["PB-14 Incidents<br/>blocked · degraded · real data seen · out-of-scope touch"] -.->|stop, record, tell the operator| STOP2([Pause])

    classDef gate fill:#fde68a,stroke:#92400e,color:#111;
    classDef stop fill:#fecaca,stroke:#991b1b,color:#111;
    classDef ship fill:#bbf7d0,stroke:#166534,color:#111;
    class PB09,PB05 gate;
    class STOP1,STOP2,INC stop;
    class HAND,PB11 ship;
```

## 2. How one asset × test pair is decided

This is the part that stops every test being run on every asset.

```mermaid
flowchart TD
    A["asset  ×  checklist item"] --> U{"Unit of the item"}
    U -->|deployment| R{"Is this host the<br/>cluster representative?"}
    U -->|host| H["evaluate on every host"]
    U -->|programme| P["evaluate once, on facts<br/>aggregated across assets"]
    R -->|no| C[/"collapsed: tested once on the representative"/]
    R -->|yes| H
    H --> M{"Already marked by hand?<br/>negative · finding · parked · ..."}
    P --> M
    M -->|yes| KEEP[/"keep the recorded outcome"/]
    M -->|no| X{"Item's 'Excluded by' ∩<br/>programme exclusions"}
    X -->|not empty| EX[/"excluded"/]
    X -->|empty| E{"Chapter 'Applies when'<br/>AND item 'Requires'<br/>over this asset's facts"}
    E -->|a clause is false on an<br/>asset or programme fact| NA[/"n/a — reason and evidence recorded"/]
    E -->|false only on a capability| BL[/"blocked — sane blockers"/]
    E -->|some fact unknown| PR[/"probe — sane probes ranks the fact<br/>by the tests it unlocks"/]
    E -->|all true| TODO[/"todo — scored and queued"/]
    PR -->|"sane fact set ... --ev"| E
    TODO --> S["score = class prior × severity range × asset weight ÷ cost<br/>class prior comes from 15k disclosed reports"]
```

Facts come from three places: the fingerprinter (`scripts/sane fp`, marked `by: fp`), the mapper's walk of the
application (`scripts/sane fact set`, `by: manual`, always wins), and implication (`needs` in
`checklist/_facts.json`: no HTTP means no login, no login means no password reset).

## 3. The CVE path

```mermaid
flowchart LR
    F["fingerprint:<br/>product name"] --> V{"version known?"}
    V -->|no| PIN["pin it: /version, health endpoints,<br/>static-file hashes, changelogs"]
    PIN --> V
    V -->|yes| L["sane cve host<br/>NVD by CPE · KEV · EPSS ·<br/>HexBrain checks · nuclei templates"]
    L --> RANK["rank: exploited in the wild ·<br/>unauthenticated · EPSS · public check"]
    RANK --> POL{"policy: patch window,<br/>known-CVE exclusion"}
    POL -->|excluded| CLOSE[/"closed: excluded"/]
    POL -->|allowed| ADV["sane cve --id CVE<br/>affected range · precondition ·<br/>the distinguishing request"]
    ADV --> CHK{"advisory's own check<br/>against the target"}
    CHK -->|not vulnerable| NEG[/"negative: back-port or<br/>virtual patch — not reported"/]
    CHK -->|vulnerable| EXP["exploit to minimal proof:<br/>/etc/hostname · id · identity document ·<br/>version string — then stop"]
    EXP -->|proof on disk| VER["PB-09 verify"]
    EXP -->|blocked 3 times| PK[/"parked with detection evidence"/]
    NEG --> VAR["10 minutes on variants:<br/>sibling endpoint · other encoding ·<br/>plugin that copied the code"]
    VAR -->|bypass found| VER
```

A version string is where this starts and never where it ends.

## 4. The research loop

```mermaid
flowchart TD
    MAP["map.md: features and the trust model"] --> INV["state 15–30 invariants<br/>'a viewer cannot cause any write'"]
    INV --> LENS["apply a lens:<br/>second-path · state-machine · identity-binding ·<br/>trust-boundary · parser-differential · time-and-concurrency ·<br/>derived-data · forgotten-surface · variant ·<br/>integration · client-trust · source"]
    LENS --> HYP["sane hyp add<br/>claim · why plausible · cheapest experiment"]
    HYP --> RANKH["rank: impact × plausibility ÷ cost"]
    RANKH --> EXPR["run the experiment<br/>with a control beside it"]
    EXPR -->|confirmed| CAND["candidate → PB-09"]
    EXPR -->|refuted| CLOSEH["sane hyp close ... refuted<br/>the note stops the next session repeating it"]
    EXPR -->|unexpected result| HYP
    EXPR -->|45 min, undecided| PARKH["parked: what is missing"]
    CLOSEH --> LENS
    CAND --> CARD["pattern generalises?<br/>propose a new checklist card"]
    LIB["library: this programme's paid reports,<br/>how fixes were bypassed elsewhere"] --> LENS
    SRC["bundles · source maps · open-source components"] --> LENS
```

## 5. Clocks

| Unit | Clock | When it runs out |
|---|---|---|
| Card, cost low / medium / high | 20 / 45 / 120 minutes | negative, parked, candidate, or one written extension |
| Hypothesis | 45 minutes to a decisive experiment | parked with what is missing |
| Verification | 45 minutes | park with the conditions observed |
| Chain attempt | 90 minutes | back to parked, missing link named |
| CVE, per product | 60 minutes | negative or parked on the CVE item |
| Research block, per deployment | 3 hours | change deployment or lens |

`scripts/sane start` stamps a card; `scripts/sane status` and the prompt hook show anything overdue; the Stop hook
will not let a turn end on an overdue card or an unverified candidate without a decision.
