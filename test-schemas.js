#!/usr/bin/env node
// Test our schemas against Kuma's validator test cases
const Ajv = require('ajv');
const yaml = require('js-yaml');
const fs = require('fs');
const path = require('path');

const SCHEMAS = JSON.parse(fs.readFileSync('schemas.json', 'utf8'));
const KUMA = '/Users/marcin.skalski/kong/kuma-fix-transparentproxy-tests';

let pass = 0, fail = 0, skip = 0;
const failures = [];

function validateSpec(kind, spec, label, expectValid) {
  const schema = SCHEMAS[kind];
  if (!schema) { skip++; return; }

  const ajv = new Ajv({ allErrors: true, strict: false });
  const valid = ajv.validate(schema, spec);

  if (expectValid && !valid) {
    fail++;
    const errs = ajv.errors.slice(0, 3).map(e =>
      `  ${e.instancePath || '/'}: ${e.message}`
    ).join('\n');
    failures.push({ label, errs, type: 'false-negative' });
  } else if (!expectValid && valid) {
    fail++;
    failures.push({ label, errs: '  (no errors produced)', type: 'false-positive' });
  } else {
    pass++;
  }
}

// Extract spec from Universal-format test YAML (strip type/name/mesh)
function extractSpec(doc) {
  if (!doc || typeof doc !== 'object') return doc;
  if (doc.type || doc.name || doc.mesh) {
    const { type, name, mesh, labels, ...rest } = doc;
    return rest;
  }
  return doc;
}

// --- Pattern 1: Entry("label", `yaml`) in DescribeTable ---
function extractEntries(content) {
  const entries = [];
  const lines = content.split('\n');
  let expectValid = true;
  let currentLabel = '';
  let currentYaml = '';
  let collecting = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.includes('should pass validation') || line.includes('DescribeValidCases')) {
      expectValid = true;
    } else if (line.includes('should validate all fields') ||
               line.includes('should not pass') ||
               line.includes('should fail') ||
               line.includes('DescribeErrorCases')) {
      expectValid = false;
    }

    // Match Entry("label", `
    const entryMatch = line.match(/Entry\(\s*"([^"]+)",\s*`$/);
    if (entryMatch) {
      currentLabel = entryMatch[1];
      currentYaml = '';
      collecting = true;
      continue;
    }

    // Match Entry("label", ` (on same line with yaml start via newline)
    const entryMatch2 = line.match(/Entry\(\s*$/);
    if (entryMatch2) {
      // next line has the label
      continue;
    }

    // Match standalone ` start after Entry( with label on previous lines
    const labelMatch = line.match(/^\s*"([^"]+)",\s*`$/);
    if (labelMatch) {
      currentLabel = labelMatch[1];
      currentYaml = '';
      collecting = true;
      continue;
    }

    if (collecting) {
      if (line.includes('`')) {
        currentYaml += line.replace(/`.*/, '');
        collecting = false;
        try {
          const spec = extractSpec(yaml.load(currentYaml));
          if (spec && typeof spec === 'object') {
            entries.push({ label: currentLabel, spec, expectValid });
          }
        } catch (e) { /* skip unparseable */ }
      } else {
        currentYaml += line + '\n';
      }
    }
  }
  return entries;
}

// --- Pattern 2: ErrorCases("label", violations, `yaml`) ---
function extractErrorCases(content) {
  const entries = [];
  const regex = /ErrorCases?\(\s*\n?\s*"([^"]+)"[\s\S]*?`\n([\s\S]*?)`\s*\)/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    try {
      const spec = extractSpec(yaml.load(match[2]));
      if (spec && typeof spec === 'object') {
        entries.push({ label: match[1], spec, expectValid: false });
      }
    } catch (e) { /* skip */ }
  }
  return entries;
}

// --- Pattern 3: testCase struct with inputYaml ---
function extractTestCases(content) {
  const entries = [];
  const regex = /Entry\("([^"]+)",\s*testCase\{\s*inputYaml:\s*`\n([\s\S]*?)`/g;
  let match;

  // Determine if this section expects valid or invalid
  let expectValid = false; // testCase pattern usually tests invalid cases

  while ((match = regex.exec(content)) !== null) {
    try {
      const spec = extractSpec(yaml.load(match[2]));
      if (spec && typeof spec === 'object') {
        entries.push({ label: match[1], spec, expectValid });
      }
    } catch (e) { /* skip */ }
  }
  return entries;
}

// --- Run tests for a policy ---
function testPolicy(policyDir, kind) {
  const testFile = path.join(policyDir, 'validator_test.go');
  if (!fs.existsSync(testFile)) return;

  const content = fs.readFileSync(testFile, 'utf8');

  // Extract all entries
  const entries = extractEntries(content);
  const errorCases = extractErrorCases(content);
  const testCases = extractTestCases(content);

  for (const { label, spec, expectValid } of entries) {
    validateSpec(kind, spec, `${kind}/${label}`, expectValid);
  }
  for (const { label, spec, expectValid } of errorCases) {
    validateSpec(kind, spec, `${kind}/err:${label}`, expectValid);
  }
  for (const { label, spec, expectValid } of testCases) {
    validateSpec(kind, spec, `${kind}/tc:${label}`, expectValid);
  }
}

// --- Test API testdata .input.yaml files ---
function testInputFiles(policyDir, kind) {
  const tdDir = path.join(policyDir, 'testdata');
  if (!fs.existsSync(tdDir)) return;

  for (const f of fs.readdirSync(tdDir).filter(f => f.endsWith('.input.yaml'))) {
    const content = fs.readFileSync(path.join(tdDir, f), 'utf8');
    const expectValid = f.includes('valid') && !f.includes('invalid');
    try {
      const spec = yaml.load(content);
      if (spec && typeof spec === 'object') {
        validateSpec(kind, spec, `${kind}/file:${f}`, expectValid);
      }
    } catch (e) { /* skip */ }
  }
}

// --- Test full Universal policies from core rules testdata ---
function testFullPolicies(dir) {
  if (!fs.existsSync(dir)) return;
  for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.input.yaml'))) {
    const content = fs.readFileSync(path.join(dir, f), 'utf8');
    const docs = yaml.loadAll(content);
    for (const doc of docs) {
      if (!doc || !doc.type || !doc.spec) continue;
      const kind = doc.type;
      if (SCHEMAS[kind]) {
        validateSpec(kind, doc.spec, `${kind}/rules:${f}`, true);
      }
    }
  }
}

// ============ Main ============

const policyMap = {
  meshaccesslog: 'MeshAccessLog',
  meshcircuitbreaker: 'MeshCircuitBreaker',
  meshfaultinjection: 'MeshFaultInjection',
  meshhealthcheck: 'MeshHealthCheck',
  meshhttproute: 'MeshHTTPRoute',
  meshloadbalancingstrategy: 'MeshLoadBalancingStrategy',
  meshmetric: 'MeshMetric',
  meshpassthrough: 'MeshPassthrough',
  meshproxypatch: 'MeshProxyPatch',
  meshratelimit: 'MeshRateLimit',
  meshretry: 'MeshRetry',
  meshtcproute: 'MeshTCPRoute',
  meshtimeout: 'MeshTimeout',
  meshtls: 'MeshTLS',
  meshtrace: 'MeshTrace',
  meshtrafficpermission: 'MeshTrafficPermission'
};

console.log('=== Policy validator tests ===\n');

for (const [dir, kind] of Object.entries(policyMap)) {
  const policyDir = path.join(KUMA, `pkg/plugins/policies/${dir}/api/v1alpha1`);
  testPolicy(policyDir, kind);
  testInputFiles(policyDir, kind);
}

console.log('\n=== Core rules full policies ===\n');

const rulesDirs = [
  'core/rules/testdata/rules/from',
  'core/rules/testdata/rules/to',
  'core/rules/testdata/rules/single',
  'core/rules/inbound/testdata/inboundrules',
  'core/rules/outbound/testdata/resourcerules',
  'core/rules/outbound/testdata/sort'
];
for (const d of rulesDirs) {
  testFullPolicies(path.join(KUMA, `pkg/plugins/policies/${d}`));
}

// Print results
console.log('\n========================================');
console.log(`TOTAL: ${pass + fail} tests | ${pass} pass | ${fail} fail | ${skip} skip`);
console.log(`Pass rate: ${((pass / (pass + fail)) * 100).toFixed(1)}%`);
console.log('========================================\n');

if (failures.length > 0) {
  const falseNeg = failures.filter(f => f.type === 'false-negative');
  const falsePos = failures.filter(f => f.type === 'false-positive');

  if (falseNeg.length > 0) {
    console.log(`--- False negatives (valid spec rejected): ${falseNeg.length} ---`);
    for (const f of falseNeg) {
      console.log(`\nFAIL: ${f.label}`);
      console.log(f.errs);
    }
  }

  if (falsePos.length > 0) {
    console.log(`\n--- False positives (invalid spec accepted): ${falsePos.length} ---`);
    for (const f of falsePos) {
      console.log(`\nFAIL: ${f.label}`);
    }
  }
}

process.exit(fail > 0 ? 1 : 0);
