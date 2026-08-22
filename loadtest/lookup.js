// Sunder M6 load test (k6, no external modules).
//
// Exercises the three hot paths against a running instance:
//   lookup_hit      POST /v1/lookup          (weighted main scenario)
//   attribute_read  GET  /v1/contacts/{cid}/attributes/email
//   oti_roundtrip   POST /v1/oti  then  POST /v1/oti/verify
//
// Thresholds encode the PLAN section 2 latency targets. Numbers measured on
// a laptop are indicative only — the contractual numbers come from the
// reference deployment (PLAN 9.2). See loadtest/README.md.
//
// Environment:
//   BASE_URL     e.g. http://localhost:8080          (required)
//   CRED         client credential with actions
//                contacts.register,lookup,attributes.read,oti.issue
//                and purpose "loadtest"              (required)
//   CRED_VERIFY  client credential with action oti.verify,
//                scope "erp", purpose "loadtest"     (required)
//   SEED_COUNT   contacts registered in setup()      (default 2000)
//   RATE         total target request rate in rps    (default 200)
//   DURATION     measurement window                  (default 1m)

import http from 'k6/http';
import { check, fail } from 'k6';

const BASE_URL = __ENV.BASE_URL;
const CRED = __ENV.CRED;
const CRED_VERIFY = __ENV.CRED_VERIFY;
const SEED_COUNT = parseInt(__ENV.SEED_COUNT || '2000', 10);
const RATE = parseInt(__ENV.RATE || '200', 10);
const DURATION = __ENV.DURATION || '1m';

// Purpose and audience must match the client grants (see README).
const PURPOSE = 'loadtest';
const AUDIENCE = 'erp'; // == scope of the CRED_VERIFY client

// Request-rate split. oti_roundtrip issues 2 requests per iteration, so its
// iteration rate is halved to keep the total at ~RATE requests per second:
//   0.70*RATE lookups + 0.20*RATE attribute reads + 2 * 0.05*RATE oti = RATE.
const lookupRate = Math.max(1, Math.round(RATE * 0.7));
const attrRate = Math.max(1, Math.round(RATE * 0.2));
const otiIterRate = Math.max(1, Math.round(RATE * 0.05));

export const options = {
  setupTimeout: '10m',
  scenarios: {
    lookup_hit: {
      executor: 'constant-arrival-rate',
      exec: 'lookupHit',
      rate: lookupRate,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 20,
      maxVUs: 200,
    },
    attribute_read: {
      executor: 'constant-arrival-rate',
      exec: 'attributeRead',
      rate: attrRate,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 10,
      maxVUs: 100,
    },
    oti_roundtrip: {
      executor: 'constant-arrival-rate',
      exec: 'otiRoundtrip',
      rate: otiIterRate,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 10,
      maxVUs: 100,
    },
  },
  thresholds: {
    // PLAN section 2 p99 targets (ms). On a laptop these are indicative;
    // the binding measurement is on the PLAN 9.2 reference deployment.
    'http_req_duration{scenario:lookup_hit}': ['p(99)<15'],
    'http_req_duration{scenario:attribute_read}': ['p(99)<15'],
    'http_req_duration{op:oti_issue}': ['p(99)<20'],
    'http_req_duration{op:oti_verify}': ['p(99)<10'],
    // constant-arrival-rate silently under-delivers when VUs run out:
    'dropped_iterations': ['count<10'],
    // Status-code checks must essentially always pass.
    'checks{scenario:lookup_hit}': ['rate>0.999'],
    'checks{scenario:attribute_read}': ['rate>0.999'],
    'checks{scenario:oti_roundtrip}': ['rate>0.999'],
  },
};

function headers(cred) {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${cred}`,
  };
}

function seedEmail(i) {
  return `seed-${i}@loadtest.example`;
}

function seedPhone(i) {
  // +38591 followed by 7 digits, deterministic per index.
  return `+38591${1000000 + i}`;
}

// setup registers SEED_COUNT contacts and returns their scoped CIDs.
// Registration is idempotent (dedup by email token), so re-runs reuse the
// same persons instead of growing the database.
export function setup() {
  if (!BASE_URL || !CRED || !CRED_VERIFY) {
    fail('BASE_URL, CRED and CRED_VERIFY are required (see loadtest/README.md)');
  }
  const cids = [];
  const batchSize = 100;
  for (let start = 0; start < SEED_COUNT; start += batchSize) {
    const requests = [];
    for (let i = start; i < Math.min(start + batchSize, SEED_COUNT); i++) {
      requests.push([
        'POST',
        `${BASE_URL}/v1/contacts`,
        JSON.stringify({ email: seedEmail(i), phone: seedPhone(i) }),
        { headers: headers(CRED) },
      ]);
    }
    const responses = http.batch(requests);
    for (const res of responses) {
      if (res.status !== 201) {
        fail(`seed registration failed: HTTP ${res.status} ${res.body}`);
      }
      cids.push(res.json('cid'));
    }
  }
  return { cids: cids };
}

function randomIndex() {
  return Math.floor(Math.random() * SEED_COUNT);
}

// lookup_hit: exact-match lookup by a seeded email — always a hit, so it
// never trips the enumeration detector or pollutes the miss metric.
export function lookupHit() {
  const res = http.post(
    `${BASE_URL}/v1/lookup`,
    JSON.stringify({ email: seedEmail(randomIndex()) }),
    { headers: headers(CRED) },
  );
  check(res, {
    'lookup is 200': (r) => r.status === 200,
    'lookup returns cid': (r) => r.status === 200 && r.json('cid') !== '',
  });
}

// attribute_read: field-level, purpose-checked decrypt of one attribute.
export function attributeRead(data) {
  const cid = data.cids[randomIndex()];
  const res = http.get(
    `${BASE_URL}/v1/contacts/${cid}/attributes/email?purpose=${PURPOSE}`,
    { headers: headers(CRED) },
  );
  check(res, {
    'attribute read is 200': (r) => r.status === 200,
  });
}

// oti_roundtrip: issue a single-use token as the source system, then verify
// (and consume) it as the target system. Two requests per iteration, tagged
// separately so each side gets its own latency threshold.
export function otiRoundtrip(data) {
  const cid = data.cids[randomIndex()];
  const issue = http.post(
    `${BASE_URL}/v1/oti`,
    JSON.stringify({ cid: cid, purpose: PURPOSE, audience: AUDIENCE }),
    { headers: headers(CRED), tags: { op: 'oti_issue' } },
  );
  const issued = check(issue, {
    'oti issue is 201': (r) => r.status === 201,
  });
  if (!issued) {
    return; // no token to verify
  }
  const verify = http.post(
    `${BASE_URL}/v1/oti/verify`,
    JSON.stringify({ token: issue.json('token'), purpose: PURPOSE, audience: AUDIENCE }),
    { headers: headers(CRED_VERIFY), tags: { op: 'oti_verify' } },
  );
  check(verify, {
    'oti verify is 200': (r) => r.status === 200,
    'oti verify returns cid': (r) => r.status === 200 && r.json('cid') !== '',
  });
}
