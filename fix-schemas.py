#!/usr/bin/env python3
"""Fix schemas.json to catch more validation errors from Go tests."""
import json

with open('schemas.json') as f:
    s = json.load(f)

fixed = []

def get_path(schema, *keys):
    """Navigate nested schema path."""
    node = schema
    for k in keys:
        node = node.get(k, {})
    return node

def set_min_items(schema, path_keys, n=1):
    """Set minItems on an array field."""
    node = schema
    for k in path_keys[:-1]:
        node = node.get(k, {})
    field = path_keys[-1]
    if field in node and node[field].get('type') == 'array':
        node[field]['minItems'] = n
        return True
    return False

# ============================================================
# 1. Empty arrays: add minItems: 1 on from/to/rules arrays
# ============================================================
for kind in s:
    for section in ['from', 'to', 'rules']:
        prop = s[kind].get('properties', {}).get(section)
        if prop and prop.get('type') == 'array' and 'minItems' not in prop:
            prop['minItems'] = 1
            fixed.append(f"{kind}.{section}: minItems=1")

# ============================================================
# 2. Empty nested arrays and minLength on strings
# ============================================================

# MeshAccessLog: backends[].file.format.json minItems: 1
for section in ['from', 'to', 'rules']:
    p = s.get('MeshAccessLog', {}).get('properties', {}).get(section, {})
    items = p.get('items', {}).get('properties', {}).get('default', {}).get('properties', {}).get('backends', {})
    if items:
        for backend_type in ['file', 'tcp']:
            bt = items.get('items', {}).get('properties', {}).get(backend_type, {})
            fmt = bt.get('properties', {}).get('format', {}).get('properties', {})
            if 'json' in fmt:
                fmt['json']['minItems'] = 1
                fixed.append(f"MeshAccessLog.{section}.backends[].{backend_type}.format.json: minItems=1")
            if 'plain' in fmt:
                fmt['plain']['minLength'] = 1
                fixed.append(f"MeshAccessLog.{section}.backends[].{backend_type}.format.plain: minLength=1")

# MeshRetry: resetHeaders minItems, backOff fields
for section in ['to', 'from', 'rules']:
    p = s.get('MeshRetry', {}).get('properties', {}).get(section, {})
    default = p.get('items', {}).get('properties', {}).get('default', {}).get('properties', {})
    for proto in ['http', 'grpc']:
        proto_props = default.get(proto, {}).get('properties', {})
        if 'rateLimitedBackOff' in proto_props:
            rlb = proto_props['rateLimitedBackOff'].get('properties', {})
            if 'resetHeaders' in rlb:
                rlb['resetHeaders']['minItems'] = 1
                fixed.append(f"MeshRetry.{section}.{proto}.rateLimitedBackOff.resetHeaders: minItems=1")

# MeshTrafficPermission: from[].default.action required or rules[].default.action required
# (handled via custom JS since it's "at least one of allow/deny/etc")

# ============================================================
# 3. Port validation: min: 1, max: 65535
# ============================================================
def add_port_constraints(node, path=""):
    """Recursively find port fields and add min/max."""
    if not isinstance(node, dict):
        return
    for key, val in node.items():
        if not isinstance(val, dict):
            continue
        current_path = f"{path}.{key}" if path else key
        if key == 'port' and val.get('type') in ['integer', 'number']:
            val['minimum'] = 1
            val['maximum'] = 65535
            fixed.append(f"port constraint: {current_path}")
        add_port_constraints(val, current_path)

for kind in s:
    add_port_constraints(s[kind], kind)

# MeshMetric: prometheus port, application port
mm = s.get('MeshMetric', {}).get('properties', {}).get('default', {}).get('properties', {})
backends = mm.get('backends', {}).get('items', {}).get('properties', {})
if 'prometheus' in backends:
    prom_port = backends['prometheus'].get('properties', {}).get('port', {})
    if prom_port.get('type') in ['integer', 'number']:
        prom_port['minimum'] = 1
        prom_port['maximum'] = 65535
        fixed.append("MeshMetric.prometheus.port: 1-65535")

apps = mm.get('applications', {}).get('items', {}).get('properties', {})
if 'port' in apps and apps['port'].get('type') in ['integer', 'number']:
    apps['port']['minimum'] = 1
    apps['port']['maximum'] = 65535
    fixed.append("MeshMetric.applications.port: 1-65535")

# ============================================================
# 4. Numeric constraints: min/max on specific fields
# ============================================================

# MeshCircuitBreaker: connectionLimits fields minimum: 1
for section in ['from', 'to', 'rules']:
    p = s.get('MeshCircuitBreaker', {}).get('properties', {}).get(section, {})
    cl = p.get('items', {}).get('properties', {}).get('default', {}).get('properties', {}).get('connectionLimits', {}).get('properties', {})
    for field in ['maxConnections', 'maxConnectionPools', 'maxPendingRequests', 'maxRetries', 'maxRequests']:
        if field in cl and cl[field].get('type') in ['integer', 'number']:
            cl[field]['minimum'] = 1
            fixed.append(f"MeshCircuitBreaker.{section}.connectionLimits.{field}: min=1")

# MeshCircuitBreaker: outlierDetection percentage fields 0-100
for section in ['from', 'to', 'rules']:
    p = s.get('MeshCircuitBreaker', {}).get('properties', {}).get(section, {})
    od = p.get('items', {}).get('properties', {}).get('default', {}).get('properties', {}).get('outlierDetection', {}).get('properties', {})
    if 'maxEjectionPercent' in od:
        od['maxEjectionPercent']['minimum'] = 0
        od['maxEjectionPercent']['maximum'] = 100
        fixed.append(f"MeshCircuitBreaker.{section}.outlierDetection.maxEjectionPercent: 0-100")
    # detectors numeric fields minimum: 1
    det = od.get('detectors', {}).get('properties', {})
    for det_name in ['totalFailures', 'gatewayFailures', 'localOriginFailures']:
        d = det.get(det_name, {}).get('properties', {})
        if 'consecutive' in d:
            d['consecutive']['minimum'] = 1
            fixed.append(f"MeshCircuitBreaker.{section}.detectors.{det_name}.consecutive: min=1")
    for det_name in ['successRate', 'failurePercentage']:
        d = det.get(det_name, {}).get('properties', {})
        for f in ['minimumHosts', 'requestVolume']:
            if f in d:
                d[f]['minimum'] = 1
                fixed.append(f"MeshCircuitBreaker.{section}.detectors.{det_name}.{f}: min=1")
        if 'threshold' in d:
            d['threshold']['minimum'] = 0
            d['threshold']['maximum'] = 100
            fixed.append(f"MeshCircuitBreaker.{section}.detectors.{det_name}.threshold: 0-100")

# MeshRetry: tcp.maxConnectAttempt minimum: 1
for section in ['to']:
    p = s.get('MeshRetry', {}).get('properties', {}).get(section, {})
    tcp = p.get('items', {}).get('properties', {}).get('default', {}).get('properties', {}).get('tcp', {}).get('properties', {})
    if 'maxConnectAttempt' in tcp:
        tcp['maxConnectAttempt']['minimum'] = 1
        fixed.append(f"MeshRetry.{section}.tcp.maxConnectAttempt: min=1")

# MeshLoadBalancingStrategy: leastRequest.activeRequestBias minimum: 0
for section in ['to']:
    p = s.get('MeshLoadBalancingStrategy', {}).get('properties', {}).get(section, {})
    lb = p.get('items', {}).get('properties', {}).get('default', {}).get('properties', {}).get('loadBalancer', {}).get('properties', {})
    lr = lb.get('leastRequest', {}).get('properties', {})
    # activeRequestBias is a string in the schema but Go validates >= 0

# MeshHealthCheck: status codes 100-599
for section in ['to']:
    p = s.get('MeshHealthCheck', {}).get('properties', {}).get(section, {})
    http = p.get('items', {}).get('properties', {}).get('default', {}).get('properties', {}).get('http', {}).get('properties', {})
    es = http.get('expectedStatuses', {})
    if es.get('type') == 'array':
        items = es.get('items', {})
        if items.get('type') in ['integer', 'number']:
            items['minimum'] = 100
            items['maximum'] = 599
            fixed.append("MeshHealthCheck.http.expectedStatuses: 100-599")

# ============================================================
# 5. Required nested fields
# ============================================================

# MeshAccessLog: file backend requires path
for section in ['from', 'to', 'rules']:
    p = s.get('MeshAccessLog', {}).get('properties', {}).get(section, {})
    backends = p.get('items', {}).get('properties', {}).get('default', {}).get('properties', {}).get('backends', {})
    file_props = backends.get('items', {}).get('properties', {}).get('file', {})
    if file_props and 'required' not in file_props:
        file_props['required'] = ['path']
        fixed.append(f"MeshAccessLog.{section}.backends[].file: required=[path]")
    tcp_props = backends.get('items', {}).get('properties', {}).get('tcp', {})
    if tcp_props and 'required' not in tcp_props:
        tcp_props['required'] = ['address']
        fixed.append(f"MeshAccessLog.{section}.backends[].tcp: required=[address]")

# MeshTrace: zipkin requires url, openTelemetry requires endpoint
trace_default = s.get('MeshTrace', {}).get('properties', {}).get('default', {}).get('properties', {})
trace_backends = trace_default.get('backends', {}).get('items', {}).get('properties', {})
if 'zipkin' in trace_backends:
    z = trace_backends['zipkin']
    if 'required' not in z:
        z['required'] = ['url']
        fixed.append("MeshTrace.default.backends[].zipkin: required=[url]")
if 'openTelemetry' in trace_backends:
    ot = trace_backends['openTelemetry']
    if 'required' not in ot:
        ot['required'] = ['endpoint']
        fixed.append("MeshTrace.default.backends[].openTelemetry: required=[endpoint]")
    # endpoint minLength
    ep = ot.get('properties', {}).get('endpoint', {})
    if ep:
        ep['minLength'] = 1
        fixed.append("MeshTrace.openTelemetry.endpoint: minLength=1")
if 'datadog' in trace_backends:
    dd = trace_backends['datadog']
    if 'required' not in dd:
        dd['required'] = ['url']
        fixed.append("MeshTrace.default.backends[].datadog: required=[url]")

# MeshTrace: tags[].name required and minLength
trace_tags = trace_default.get('tags', {}).get('items', {}).get('properties', {})
if 'name' in trace_tags:
    trace_tags['name']['minLength'] = 1
    fixed.append("MeshTrace.default.tags[].name: minLength=1")
# tag items require name
trace_tag_item = trace_default.get('tags', {}).get('items', {})
if trace_tag_item and 'required' not in trace_tag_item:
    trace_tag_item['required'] = ['name']
    fixed.append("MeshTrace.default.tags[]: required=[name]")

# MeshTrace: sampling fields 0-100
sampling = trace_default.get('sampling', {}).get('properties', {})
for field in ['overall', 'random', 'client']:
    if field in sampling:
        # These can be numbers or strings, add validation for numbers
        if sampling[field].get('type') in ['integer', 'number']:
            sampling[field]['minimum'] = 0
            sampling[field]['maximum'] = 100
            fixed.append(f"MeshTrace.sampling.{field}: 0-100")

# ============================================================
# Write output
# ============================================================
with open('schemas.json', 'w') as f:
    json.dump(s, f, indent=2)

print(f"Applied {len(fixed)} fixes:")
for f in fixed:
    print(f"  - {f}")
