// Shared semantic validator - used by both index.html and test-schemas.js
// This file is designed to work in both browser and Node.js environments.

const TOP_TARGETREF_KINDS = {
  MeshAccessLog: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'MeshHTTPRoute', 'Dataplane', 'MeshExternalService', 'MeshMultiZoneService'],
  MeshCircuitBreaker: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'MeshHTTPRoute', 'Dataplane', 'MeshExternalService', 'MeshMultiZoneService'],
  MeshFaultInjection: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'MeshHTTPRoute', 'Dataplane', 'MeshExternalService', 'MeshMultiZoneService'],
  MeshHealthCheck: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'MeshHTTPRoute', 'Dataplane', 'MeshExternalService', 'MeshMultiZoneService'],
  MeshHTTPRoute: ['Mesh', 'MeshSubset', 'MeshService', 'MeshGateway', 'Dataplane'],
  MeshLoadBalancingStrategy: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'MeshHTTPRoute', 'Dataplane', 'MeshExternalService', 'MeshMultiZoneService'],
  MeshMetric: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'Dataplane', 'MeshExternalService', 'MeshMultiZoneService'],
  MeshPassthrough: ['Mesh', 'MeshSubset', 'Dataplane'],
  MeshProxyPatch: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'Dataplane'],
  MeshRateLimit: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'MeshHTTPRoute', 'Dataplane', 'MeshExternalService', 'MeshMultiZoneService'],
  MeshRetry: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'MeshHTTPRoute', 'Dataplane', 'MeshExternalService', 'MeshMultiZoneService'],
  MeshTCPRoute: ['Mesh', 'MeshSubset', 'MeshService', 'MeshGateway', 'Dataplane'],
  MeshTimeout: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'MeshHTTPRoute', 'Dataplane', 'MeshExternalService', 'MeshMultiZoneService'],
  MeshTLS: ['Mesh', 'MeshSubset', 'Dataplane'],
  MeshTrace: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'Dataplane'],
  MeshTrafficPermission: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset', 'MeshGateway', 'Dataplane', 'MeshExternalService', 'MeshMultiZoneService'],
};

const TO_TARGETREF_KINDS = {
  MeshAccessLog: ['Mesh', 'MeshService', 'MeshExternalService', 'MeshMultiZoneService', 'MeshHTTPRoute'],
  MeshCircuitBreaker: ['Mesh', 'MeshService', 'MeshExternalService', 'MeshMultiZoneService', 'MeshHTTPRoute'],
  MeshHealthCheck: ['Mesh', 'MeshService', 'MeshExternalService', 'MeshMultiZoneService', 'MeshHTTPRoute'],
  MeshLoadBalancingStrategy: ['Mesh', 'MeshService', 'MeshMultiZoneService', 'MeshHTTPRoute'],
  MeshRateLimit: ['Mesh', 'MeshService', 'MeshExternalService', 'MeshMultiZoneService', 'MeshHTTPRoute'],
  MeshRetry: ['Mesh', 'MeshService', 'MeshExternalService', 'MeshMultiZoneService', 'MeshHTTPRoute'],
  MeshTCPRoute: ['MeshService', 'MeshMultiZoneService', 'MeshExternalService', 'Mesh'],
  MeshTimeout: ['Mesh', 'MeshService', 'MeshExternalService', 'MeshMultiZoneService', 'MeshHTTPRoute'],
};

const FROM_TARGETREF_KINDS = {
  MeshAccessLog: ['Mesh'],
  MeshCircuitBreaker: ['Mesh'],
  MeshFaultInjection: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset'],
  MeshRateLimit: ['Mesh'],
  MeshTimeout: ['Mesh'],
  MeshTLS: ['Mesh'],
  MeshTrafficPermission: ['Mesh', 'MeshSubset', 'MeshService', 'MeshServiceSubset'],
};

function validateSemantic(kind, spec) {
  const errors = [];

  const hasTo = Array.isArray(spec.to) && spec.to.length > 0;
  const hasFrom = Array.isArray(spec.from) && spec.from.length > 0;
  const hasRules = Array.isArray(spec.rules) && spec.rules.length > 0;

  // -- from + rules mutual exclusivity --
  const policiesWithMutex = ['MeshAccessLog', 'MeshCircuitBreaker', 'MeshTimeout', 'MeshRateLimit', 'MeshTLS', 'MeshTrafficPermission', 'MeshFaultInjection'];
  if (policiesWithMutex.includes(kind)) {
    if (hasRules && (hasFrom || hasTo))
      errors.push({ msg: '"to" and "from" must be empty when "rules" is defined', path: 'spec' });
  }

  // -- require at least one section (policies only) --
  const policyKinds = [
    'MeshAccessLog', 'MeshCircuitBreaker', 'MeshFaultInjection', 'MeshHealthCheck',
    'MeshHTTPRoute', 'MeshLoadBalancingStrategy', 'MeshRateLimit', 'MeshRetry',
    'MeshTCPRoute', 'MeshTimeout', 'MeshTLS', 'MeshTrafficPermission',
  ];
  const specLevelDefault = ['MeshTrace', 'MeshMetric', 'MeshPassthrough', 'MeshProxyPatch'];
  if (policyKinds.includes(kind)) {
    if (!hasTo && !hasFrom && !hasRules)
      errors.push({ msg: 'at least one of "from", "to", or "rules" must be defined', path: 'spec' });
  }

  // -- MeshGateway/MeshHTTPRoute top-level restrictions --
  const topKind = spec.targetRef?.kind;
  const gatewayOrRoute = topKind === 'MeshGateway' || topKind === 'MeshHTTPRoute';
  if (gatewayOrRoute) {
    // from not allowed for these policies when targeting gateway/route
    const noFromPolicies = ['MeshTimeout', 'MeshRetry', 'MeshRateLimit'];
    if (noFromPolicies.includes(kind) && hasFrom)
      errors.push({ msg: '"from" is not allowed when targeting a gateway or route', path: 'spec.from' });
    // to[] targetRef restricted when targeting gateway/route
    if (hasTo) {
      const gatewayToKinds = {
        MeshAccessLog: topKind === 'MeshGateway' ? ['Mesh'] : undefined,
        MeshTimeout: ['Mesh', 'MeshExternalService'],
        MeshRetry: ['Mesh', 'MeshExternalService'],
      };
      const allowed = gatewayToKinds[kind];
      if (allowed) {
        spec.to.forEach((item, i) => {
          if (item.targetRef?.kind && !allowed.includes(item.targetRef.kind))
            errors.push({ msg: `targetRef kind "${item.targetRef.kind}" is not supported when top-level targets ${topKind}`, path: `spec.to[${i}].targetRef.kind` });
        });
      }
    }
  }
  // MeshLoadBalancingStrategy: MeshGateway + loadBalancer → to must be Mesh only
  if (kind === 'MeshLoadBalancingStrategy' && topKind === 'MeshGateway' && hasTo) {
    spec.to.forEach((item, i) => {
      if (item.default?.loadBalancer && item.targetRef?.kind && item.targetRef.kind !== 'Mesh')
        errors.push({ msg: `targetRef kind "${item.targetRef.kind}" is not supported when loadBalancer is set with MeshGateway`, path: `spec.to[${i}].targetRef.kind` });
    });
  }

  // -- top-level targetRef kind validation --
  if (spec.targetRef?.kind && TOP_TARGETREF_KINDS[kind]) {
    if (!TOP_TARGETREF_KINDS[kind].includes(spec.targetRef.kind))
      errors.push({ msg: `targetRef kind "${spec.targetRef.kind}" is not supported`, path: 'spec.targetRef.kind' });
  }

  // -- sectionName only for inbound policies --
  if (spec.targetRef?.sectionName) {
    const isOutbound = ['MeshTimeout', 'MeshCircuitBreaker', 'MeshRetry', 'MeshAccessLog',
      'MeshRateLimit', 'MeshLoadBalancingStrategy', 'MeshHealthCheck'].includes(kind);
    if (isOutbound)
      errors.push({ msg: 'sectionName can only be used with inbound policies', path: 'spec.targetRef.sectionName' });
  }

  // -- to[] targetRef kind validation --
  if (hasTo && TO_TARGETREF_KINDS[kind]) {
    spec.to.forEach((item, i) => {
      if (item.targetRef?.kind && !TO_TARGETREF_KINDS[kind].includes(item.targetRef.kind))
        errors.push({ msg: `targetRef kind "${item.targetRef.kind}" is not supported`, path: `spec.to[${i}].targetRef.kind` });
    });
  }

  // -- from[] targetRef kind validation --
  if (hasFrom && FROM_TARGETREF_KINDS[kind]) {
    spec.from.forEach((item, i) => {
      if (item.targetRef?.kind && !FROM_TARGETREF_KINDS[kind].includes(item.targetRef.kind))
        errors.push({ msg: `targetRef kind "${item.targetRef.kind}" is not supported`, path: `spec.from[${i}].targetRef.kind` });
    });
  }

  // -- to[]/from[] require default with content --
  if (hasTo) {
    spec.to.forEach((item, i) => {
      if (!item.default || typeof item.default !== 'object' || Object.keys(item.default).length === 0) {
        if (['MeshAccessLog'].includes(kind))
          errors.push({ msg: 'default.backends must be defined', path: `spec.to[${i}].default.backends` });
        else if (['MeshTimeout'].includes(kind) && !item.default)
          errors.push({ msg: 'missing timeout configuration', path: `spec.to[${i}].default` });
        else if (['MeshCircuitBreaker'].includes(kind))
          errors.push({ msg: 'missing configuration', path: `spec.to[${i}].default` });
      }
    });
  }
  if (hasFrom) {
    spec.from.forEach((item, i) => {
      if (!item.default || typeof item.default !== 'object' || Object.keys(item.default).length === 0) {
        if (['MeshAccessLog'].includes(kind))
          errors.push({ msg: 'default.backends must be defined', path: `spec.from[${i}].default.backends` });
        else if (['MeshCircuitBreaker'].includes(kind))
          errors.push({ msg: 'missing configuration', path: `spec.from[${i}].default` });
      }
    });
  }

  // -- MeshCircuitBreaker: outlierDetection detectors --
  if (kind === 'MeshCircuitBreaker') {
    const checkCB = (items, prefix) => {
      if (!Array.isArray(items)) return;
      items.forEach((item, i) => {
        const od = item.default?.outlierDetection;
        if (od) {
          if (!od.detectors || typeof od.detectors !== 'object' || Object.keys(od.detectors).length === 0)
            errors.push({ msg: 'detectors must be defined', path: `${prefix}[${i}].default.outlierDetection.detectors` });
          if (od.detectors) {
            for (const [name, det] of Object.entries(od.detectors)) {
              if (typeof det === 'object' && det !== null && Object.keys(det).length === 0)
                errors.push({ msg: 'detector must not be empty', path: `${prefix}[${i}].default.outlierDetection.detectors.${name}` });
              if (det?.standardDeviationFactor !== undefined) {
                const sdf = typeof det.standardDeviationFactor === 'string' ? parseFloat(det.standardDeviationFactor) : det.standardDeviationFactor;
                if (isNaN(sdf))
                  errors.push({ msg: 'must be a valid number', path: `${prefix}[${i}].default.outlierDetection.detectors.${name}.standardDeviationFactor` });
                else if (sdf < 0)
                  errors.push({ msg: 'must be >= 0', path: `${prefix}[${i}].default.outlierDetection.detectors.${name}.standardDeviationFactor` });
              }
            }
          }
          if (od.healthyPanicThreshold !== undefined) {
            const hpt = typeof od.healthyPanicThreshold === 'string' ? parseFloat(od.healthyPanicThreshold) : od.healthyPanicThreshold;
            if (!isNaN(hpt) && (hpt < 0 || hpt > 100))
              errors.push({ msg: 'must be between 0 and 100', path: `${prefix}[${i}].default.outlierDetection.healthyPanicThreshold` });
          }
        }
      });
    };
    checkCB(spec.from, 'spec.from');
    checkCB(spec.to, 'spec.to');
    checkCB(spec.rules, 'spec.rules');
  }

  // -- MeshTrace specific --
  if (kind === 'MeshTrace') {
    if (!spec.default?.backends)
      errors.push({ msg: 'default.backends must be defined', path: 'spec.default.backends' });
    const backends = spec.default?.backends;
    if (Array.isArray(backends)) {
      if (backends.length > 1)
        errors.push({ msg: 'must have zero or one backend defined', path: 'spec.default.backends' });
      backends.forEach((b, i) => {
        if (b.type === 'Zipkin' && !b.zipkin)
          errors.push({ msg: 'zipkin must be defined', path: `spec.default.backends[${i}].zipkin` });
        if (b.type === 'Datadog' && !b.datadog)
          errors.push({ msg: 'datadog must be defined', path: `spec.default.backends[${i}].datadog` });
        if (b.type === 'OpenTelemetry' && !b.openTelemetry)
          errors.push({ msg: 'openTelemetry must be defined', path: `spec.default.backends[${i}].openTelemetry` });
        if (b.zipkin?.url) {
          try { new URL(b.zipkin.url); } catch { errors.push({ msg: 'must be a valid url', path: `spec.default.backends[${i}].zipkin.url` }); }
        }
        if (b.datadog?.url) {
          try {
            const u = new URL(b.datadog.url);
            if (u.protocol !== 'http:') errors.push({ msg: 'scheme must be http', path: `spec.default.backends[${i}].datadog.url` });
            if (u.pathname && u.pathname !== '/') errors.push({ msg: 'path must not be defined', path: `spec.default.backends[${i}].datadog.url` });
            const port = parseInt(u.port);
            if (!port) errors.push({ msg: 'port must be defined', path: `spec.default.backends[${i}].datadog.url` });
            else if (port < 1 || port > 65535) errors.push({ msg: 'port must be valid (1-65535)', path: `spec.default.backends[${i}].datadog.url` });
          } catch { errors.push({ msg: 'must be a valid url', path: `spec.default.backends[${i}].datadog.url` }); }
        }
        if (b.openTelemetry?.endpoint) {
          const ep = b.openTelemetry.endpoint;
          if (ep.includes('://') || ep.includes('/'))
            errors.push({ msg: 'must be in host:port format, not a URL', path: `spec.default.backends[${i}].openTelemetry.endpoint` });
        }
      });
    }
    const tags = spec.default?.tags;
    if (Array.isArray(tags)) {
      tags.forEach((t, i) => {
        if (!t.literal && !t.header)
          errors.push({ msg: 'tag must have only one type defined: header, literal', path: `spec.default.tags[${i}]` });
      });
    }
    const sampling = spec.default?.sampling;
    if (sampling) {
      for (const [field, val] of Object.entries(sampling)) {
        const num = typeof val === 'string' ? parseFloat(val) : val;
        if (isNaN(num)) errors.push({ msg: 'string is not a number', path: `spec.default.sampling.${field}` });
        else if (num < 0 || num > 100) errors.push({ msg: 'must be between 0 and 100', path: `spec.default.sampling.${field}` });
      }
    }
    if (spec.targetRef?.kind === 'MeshGateway' && spec.targetRef.tags)
      errors.push({ msg: 'must not be set with kind MeshGateway', path: 'spec.targetRef.tags' });
  }

  // -- MeshMetric specific --
  if (kind === 'MeshMetric') {
    const backends = spec.default?.backends;
    if (Array.isArray(backends)) {
      backends.forEach((b, i) => {
        if (b.type === 'Prometheus' && !b.prometheus)
          errors.push({ msg: 'prometheus must be defined', path: `spec.default.backends.backend[${i}].prometheus` });
        if (b.type === 'OpenTelemetry' && !b.openTelemetry)
          errors.push({ msg: 'openTelemetry must be defined', path: `spec.default.backends.backend[${i}].openTelemetry` });
        if (b.openTelemetry?.endpoint) {
          const ep = b.openTelemetry.endpoint;
          if (ep.includes('://')) errors.push({ msg: 'must not use schema', path: `spec.default.backends.backend[${i}].openTelemetry.endpoint` });
          else if (!ep.includes(':')) errors.push({ msg: 'must be a valid url', path: `spec.default.backends.backend[${i}].openTelemetry.endpoint` });
        }
      });
    }
    const profiles = spec.default?.sidecar?.profiles;
    if (profiles) {
      const validProfiles = ['All', 'None', 'Basic'];
      const validTypes = ['Regex', 'Prefix', 'Exact'];
      if (Array.isArray(profiles.appendProfiles)) {
        profiles.appendProfiles.forEach((p, i) => {
          if (!validProfiles.includes(p.name))
            errors.push({ msg: `unrecognized profile name '${p.name}'`, path: `spec.default.sidecar.profiles.appendProfiles[${i}].name` });
        });
      }
      if (Array.isArray(profiles.include)) {
        profiles.include.forEach((p, i) => {
          if (!validTypes.includes(p.type))
            errors.push({ msg: `unrecognized type '${p.type}'`, path: `spec.default.sidecar.profiles.include[${i}].type` });
        });
      }
      if (Array.isArray(profiles.exclude)) {
        profiles.exclude.forEach((p, i) => {
          if (p.type === 'Regex' && p.match) {
            try { new RegExp(p.match); } catch { errors.push({ msg: 'invalid regex', path: `spec.default.sidecar.profiles.exclude[${i}].match` }); }
          }
        });
      }
    }
  }

  // -- MeshAccessLog: backend type must have corresponding config --
  if (kind === 'MeshAccessLog') {
    const checkBackends = (items, prefix) => {
      if (!Array.isArray(items)) return;
      items.forEach((item, i) => {
        const backends = item.default?.backends;
        if (Array.isArray(backends)) {
          backends.forEach((b, j) => {
            if (b.type === 'File' && !b.file) errors.push({ msg: 'file must be defined', path: `${prefix}[${i}].default.backends[${j}].file` });
            if (b.type === 'Tcp' && !b.tcp) errors.push({ msg: 'tcp must be defined', path: `${prefix}[${i}].default.backends[${j}].tcp` });
            if (b.type === 'OpenTelemetry' && !b.openTelemetry) errors.push({ msg: 'openTelemetry must be defined', path: `${prefix}[${i}].default.backends[${j}].openTelemetry` });
            if (b.file?.path && !b.file.path.match(/^[a-zA-Z0-9\/_\-\.]+$/))
              errors.push({ msg: 'file backend requires a valid path', path: `${prefix}[${i}].default.backends[${j}].file.path` });
            if (b.tcp?.address && !b.tcp.address.match(/^[a-zA-Z0-9\.\-]+:\d+$/) && !b.tcp.address.match(/^https?:\/\/.+/))
              errors.push({ msg: 'tcp backend requires valid address', path: `${prefix}[${i}].default.backends[${j}].tcp.address` });
            // format type must match
            if (b.file?.format) {
              if (b.file.format.type === 'Plain' && !b.file.format.plain)
                errors.push({ msg: 'plain must be defined when type is Plain', path: `${prefix}[${i}].default.backends[${j}].file.format.plain` });
            }
            if (b.tcp?.format) {
              if (b.tcp.format.type === 'Plain' && !b.tcp.format.plain)
                errors.push({ msg: 'plain must be defined when type is Plain', path: `${prefix}[${i}].default.backends[${j}].tcp.format.plain` });
            }
            // format: json must have items with key field
            if (b.file?.format?.json && Array.isArray(b.file.format.json)) {
              b.file.format.json.forEach((entry, k) => {
                if (!entry.key || entry.key === '')
                  errors.push({ msg: 'key must not be empty', path: `${prefix}[${i}].default.backends[${j}].file.format.json[${k}].key` });
              });
            }
            if (b.tcp?.format?.json && Array.isArray(b.tcp.format.json)) {
              b.tcp.format.json.forEach((entry, k) => {
                if (!entry.key || entry.key === '')
                  errors.push({ msg: 'key must not be empty', path: `${prefix}[${i}].default.backends[${j}].tcp.format.json[${k}].key` });
              });
            }
          });
        }
      });
    };
    checkBackends(spec.from, 'spec.from');
    checkBackends(spec.to, 'spec.to');
    checkBackends(spec.rules, 'spec.rules');
  }

  // -- MeshRateLimit specific --
  if (kind === 'MeshRateLimit') {
    const checkRateLimit = (items, prefix) => {
      if (!Array.isArray(items)) return;
      items.forEach((item, i) => {
        const d = item.default;
        if (!d || typeof d !== 'object') return;
        const local = d.local;
        if (d && Object.keys(d).length === 0)
          errors.push({ msg: 'default must not be empty', path: `${prefix}[${i}].default` });
        if (local) {
          if (!local.http && !local.tcp)
            errors.push({ msg: 'at least one of http or tcp must be defined', path: `${prefix}[${i}].default.local` });
          if (local.http && Object.keys(local.http).length === 0)
            errors.push({ msg: 'http must not be empty', path: `${prefix}[${i}].default.local.http` });
          if (local.tcp && Object.keys(local.tcp).length === 0)
            errors.push({ msg: 'tcp must not be empty', path: `${prefix}[${i}].default.local.tcp` });
          // http.requestRate.num must be > 0
          if (local.http?.requestRate?.num !== undefined && local.http.requestRate.num < 1)
            errors.push({ msg: 'must be >= 1', path: `${prefix}[${i}].default.local.http.requestRate.num` });
          // tcp.connectionRate.num must be > 0
          if (local.tcp?.connectionRate?.num !== undefined && local.tcp.connectionRate.num < 1)
            errors.push({ msg: 'must be >= 1', path: `${prefix}[${i}].default.local.tcp.connectionRate.num` });
        }
      });
    };
    checkRateLimit(spec.from, 'spec.from');
    checkRateLimit(spec.to, 'spec.to');
    checkRateLimit(spec.rules, 'spec.rules');

    // from[] targetRef cannot be MeshService for tcp-only or mixed
    if (hasFrom) {
      spec.from.forEach((item, i) => {
        if (item.targetRef?.kind === 'MeshService') {
          errors.push({ msg: 'kind MeshService is not allowed for from targetRef', path: `spec.from[${i}].targetRef.kind` });
        }
      });
    }
  }

  // -- MeshProxyPatch: exactly one modification type per entry --
  if (kind === 'MeshProxyPatch') {
    const mods = spec.default?.appendModifications;
    if (Array.isArray(mods)) {
      mods.forEach((m, i) => {
        const types = ['cluster', 'listener', 'networkFilter', 'httpFilter', 'virtualHost'].filter(t => m[t]);
        if (types.length === 0)
          errors.push({ msg: 'exactly one modification can be defined at a time', path: `spec.default.appendModifications[${i}]` });
        else if (types.length > 1)
          errors.push({ msg: 'exactly one modification can be defined at a time', path: `spec.default.appendModifications[${i}]` });
      });
    }
  }

  // -- MeshLoadBalancingStrategy specific --
  if (kind === 'MeshLoadBalancingStrategy') {
    if (hasTo) {
      spec.to.forEach((item, i) => {
        const d = item.default;
        if (!d) return;
        const checkHashPolicies = (policies, prefix) => {
          if (!Array.isArray(policies)) return;
          policies.forEach((hp, j) => {
            const typeMap = { Header: 'header', Cookie: 'cookie', Connection: 'connection', QueryParameter: 'queryParameter', FilterState: 'filterState', SourceIP: 'connection' };
            const expected = typeMap[hp.type];
            if (expected && !hp[expected])
              errors.push({ msg: `${expected} must be defined`, path: `${prefix}[${j}].${expected}` });
          });
        };
        checkHashPolicies(d.hashPolicies, `spec.to[${i}].default.hashPolicies`);
        const lb = d.loadBalancer;
        if (lb?.ringHash?.hashPolicies) checkHashPolicies(lb.ringHash.hashPolicies, `spec.to[${i}].default.loadBalancer.ringHash.hashPolicies`);
        if (lb?.maglev?.hashPolicies) checkHashPolicies(lb.maglev.hashPolicies, `spec.to[${i}].default.loadBalancer.maglev.hashPolicies`);
        const checkCookiePath = (policies, prefix) => {
          if (!Array.isArray(policies)) return;
          policies.forEach((hp, j) => {
            if (hp.cookie?.path && !hp.cookie.path.startsWith('/'))
              errors.push({ msg: 'must be an absolute path', path: `${prefix}[${j}].cookie.path` });
          });
        };
        checkCookiePath(d.hashPolicies, `spec.to[${i}].default.hashPolicies`);
        if (lb?.ringHash?.hashPolicies) checkCookiePath(lb.ringHash.hashPolicies, `spec.to[${i}].default.loadBalancer.ringHash.hashPolicies`);
        if (lb?.maglev?.hashPolicies) checkCookiePath(lb.maglev.hashPolicies, `spec.to[${i}].default.loadBalancer.maglev.hashPolicies`);
        if (d.hashPolicies && lb?.ringHash?.hashPolicies)
          errors.push({ msg: 'hashPolicies already specified in the root level', path: `spec.to[${i}].default.loadBalancer.ringHash.hashPolicies` });
        if (d.hashPolicies && lb?.maglev?.hashPolicies)
          errors.push({ msg: 'hashPolicies already specified in the root level', path: `spec.to[${i}].default.loadBalancer.maglev.hashPolicies` });
        if (item.targetRef?.kind === 'MeshHTTPRoute') {
          if (d.loadBalancer) errors.push({ msg: 'field is not allowed when targetRef.kind is MeshHTTPRoute', path: `spec.to[${i}].default.loadBalancer` });
          if (d.localityAwareness) errors.push({ msg: 'field is not allowed when targetRef.kind is MeshHTTPRoute', path: `spec.to[${i}].default.localityAwareness` });
        }
        if (item.targetRef?.kind === 'MeshService' && item.targetRef?.sectionName && d.localityAwareness?.crossZone)
          errors.push({ msg: 'must not be set: MeshService traffic is local', path: `spec.to[${i}].default.localityAwareness.crossZone` });
        const failover = d.localityAwareness?.crossZone?.failover;
        if (Array.isArray(failover)) {
          failover.forEach((f, j) => {
            if (f.from?.zones && f.from.zones.length === 0)
              errors.push({ msg: 'must not be empty', path: `spec.to[${i}].default.localityAwareness.crossZone.failover[${j}].from.zones` });
            if (Array.isArray(f.from?.zones)) {
              f.from.zones.forEach((z, k) => {
                if (!z) errors.push({ msg: 'must not be empty', path: `spec.to[${i}].default.localityAwareness.crossZone.failover[${j}].from.zones[${k}]` });
              });
            }
            if (f.to?.type === 'None' && f.to.zones?.length > 0)
              errors.push({ msg: 'must be empty when type is None', path: `spec.to[${i}].default.localityAwareness.crossZone.failover[${j}].to.zones` });
            if (f.to?.type === 'Any' && f.to.zones?.length > 0)
              errors.push({ msg: 'must be empty when type is Any', path: `spec.to[${i}].default.localityAwareness.crossZone.failover[${j}].to.zones` });
            if (f.to?.type === 'Only' && (!f.to.zones || f.to.zones.length === 0))
              errors.push({ msg: 'must not be empty when type is Only', path: `spec.to[${i}].default.localityAwareness.crossZone.failover[${j}].to.zones` });
            if (f.to?.type === 'AnyExcept' && (!f.to.zones || f.to.zones.length === 0))
              errors.push({ msg: 'must not be empty when type is AnyExcept', path: `spec.to[${i}].default.localityAwareness.crossZone.failover[${j}].to.zones` });
          });
        }
        const ft = d.localityAwareness?.crossZone?.failoverThreshold;
        if (ft) {
          const pct = typeof ft.percentage === 'string' ? parseFloat(ft.percentage) : ft.percentage;
          if (isNaN(pct)) errors.push({ msg: 'string must be a valid number', path: `spec.to[${i}].default.localityAwareness.crossZone.failoverThreshold.percentage` });
          else if (pct <= 0) errors.push({ msg: 'must be greater than 0', path: `spec.to[${i}].default.localityAwareness.crossZone.failoverThreshold.percentage` });
        }
        const at = d.localityAwareness?.localZone?.affinityTags;
        if (Array.isArray(at)) {
          at.forEach((tag, j) => {
            if (!tag.key) errors.push({ msg: 'must not be empty', path: `spec.to[${i}].default.localityAwareness.localZone.affinityTags[${j}].key` });
            if (tag.weight !== undefined && tag.weight <= 0) errors.push({ msg: 'must be greater than 0', path: `spec.to[${i}].default.localityAwareness.localZone.affinityTags[${j}].weight` });
          });
          const hasWeight = at.some(t => t.weight !== undefined);
          const allWeight = at.every(t => t.weight !== undefined);
          if (hasWeight && !allWeight)
            errors.push({ msg: 'all or none affinity tags should have weight', path: `spec.to[${i}].default.localityAwareness.localZone.affinityTags` });
        }
        if (lb?.leastRequest?.activeRequestBias !== undefined) {
          const bias = typeof lb.leastRequest.activeRequestBias === 'string' ? parseFloat(lb.leastRequest.activeRequestBias) : lb.leastRequest.activeRequestBias;
          if (bias < 0) errors.push({ msg: 'must be greater or equal then: 0', path: `spec.to[${i}].default.loadBalancer.leastRequest.activeRequestBias` });
        }
      });
    }
  }

  // -- MeshTCPRoute: context-dependent to[] validation --
  if (kind === 'MeshTCPRoute' && hasTo) {
    const topIsGateway = spec.targetRef?.kind === 'MeshGateway';
    const tcpToAllowed = topIsGateway ? ['Mesh'] : ['MeshService', 'MeshExternalService', 'MeshMultiZoneService'];
    spec.to.forEach((item, i) => {
      if (item.targetRef?.kind && !tcpToAllowed.includes(item.targetRef.kind))
        errors.push({ msg: `targetRef kind "${item.targetRef.kind}" is not supported`, path: `spec.to[${i}].targetRef.kind` });
      // backendRefs: weight must be > 0
      if (item.rules) {
        item.rules.forEach((rule, j) => {
          const refs = rule.default?.backendRefs;
          if (Array.isArray(refs)) {
            refs.forEach((ref, k) => {
              if (ref.weight !== undefined && ref.weight < 0)
                errors.push({ msg: 'weight must be >= 0', path: `spec.to[${i}].rules[${j}].default.backendRefs[${k}].weight` });
            });
          }
        });
      }
    });
  }

  // -- MeshTCPRoute: backendRefs validation --
  if (kind === 'MeshTCPRoute' && hasTo) {
    spec.to.forEach((item, i) => {
      if (item.rules) {
        item.rules.forEach((rule, j) => {
          const refs = rule.default?.backendRefs;
          if (Array.isArray(refs)) {
            refs.forEach((ref, k) => {
              if (ref.kind === 'MeshMultiZoneService' && ref.port === undefined)
                errors.push({ msg: 'port must be defined for MeshMultiZoneService', path: `spec.to[${i}].rules[${j}].default.backendRefs[${k}].port` });
              if (ref.kind === 'MeshServiceSubset' && !ref.name)
                errors.push({ msg: 'name must be set with kind MeshServiceSubset', path: `spec.to[${i}].rules[${j}].default.backendRefs[${k}].name` });
            });
          }
        });
      }
    });
  }

  // -- MeshTrafficPermission specific --
  if (kind === 'MeshTrafficPermission') {
    if (hasFrom) {
      spec.from.forEach((item, i) => {
        if (!item.default || !item.default.action)
          errors.push({ msg: 'default.action must be defined', path: `spec.from[${i}].default` });
      });
    }
    if (hasRules) {
      spec.rules.forEach((rule, i) => {
        const d = rule.default;
        if (!d) return;
        const hasAllow = Array.isArray(d.allow) && d.allow.length > 0;
        const hasDeny = Array.isArray(d.deny) && d.deny.length > 0;
        const hasShadow = Array.isArray(d.allowWithShadowDeny) && d.allowWithShadowDeny.length > 0;
        if (!hasAllow && !hasDeny && !hasShadow)
          errors.push({ msg: "at least one of 'allow', 'allowWithShadowDeny', 'deny' must be defined", path: `spec.rules[${i}]` });
      });
    }
  }

  // -- MeshRetry specific --
  if (kind === 'MeshRetry') {
    const checkRetry = (items, prefix) => {
      if (!Array.isArray(items)) return;
      items.forEach((item, i) => {
        const d = item.default;
        if (!d || typeof d !== 'object') return;
        if (Object.keys(d).length === 0)
          errors.push({ msg: 'default must not be empty', path: `${prefix}[${i}].default` });
        // empty http/grpc/tcp sections
        if (d.http && typeof d.http === 'object' && Object.keys(d.http).length === 0)
          errors.push({ msg: 'http must not be empty', path: `${prefix}[${i}].default.http` });
        if (d.grpc && typeof d.grpc === 'object' && Object.keys(d.grpc).length === 0)
          errors.push({ msg: 'grpc must not be empty', path: `${prefix}[${i}].default.grpc` });
        if (d.tcp && typeof d.tcp === 'object' && Object.keys(d.tcp).length === 0)
          errors.push({ msg: 'tcp must not be empty', path: `${prefix}[${i}].default.tcp` });
        // empty backOff
        if (d.http?.backOff && typeof d.http.backOff === 'object' && Object.keys(d.http.backOff).length === 0)
          errors.push({ msg: 'backOff must not be empty', path: `${prefix}[${i}].default.http.backOff` });
        if (d.grpc?.backOff && typeof d.grpc.backOff === 'object' && Object.keys(d.grpc.backOff).length === 0)
          errors.push({ msg: 'backOff must not be empty', path: `${prefix}[${i}].default.grpc.backOff` });
        // empty rateLimitedBackOff
        if (d.http?.rateLimitedBackOff && typeof d.http.rateLimitedBackOff === 'object' && Object.keys(d.http.rateLimitedBackOff).length === 0)
          errors.push({ msg: 'rateLimitedBackOff must not be empty', path: `${prefix}[${i}].default.http.rateLimitedBackOff` });
        if (d.grpc?.rateLimitedBackOff && typeof d.grpc.rateLimitedBackOff === 'object' && Object.keys(d.grpc.rateLimitedBackOff).length === 0)
          errors.push({ msg: 'rateLimitedBackOff must not be empty', path: `${prefix}[${i}].default.grpc.rateLimitedBackOff` });
        // hostSelection validation
        if (Array.isArray(d.http?.hostSelection)) {
          d.http.hostSelection.forEach((hs, j) => {
            if (hs.predicate === 'OmitHostsWithTags' && (!hs.tags || Object.keys(hs.tags).length === 0))
              errors.push({ msg: 'tags required when predicate is OmitHostsWithTags', path: `${prefix}[${i}].default.http.hostSelection[${j}].tags` });
            if (hs.predicate === 'OmitPreviousPriorities' && hs.updateFrequency !== undefined && hs.updateFrequency < 1)
              errors.push({ msg: 'updateFrequency must be >= 1', path: `${prefix}[${i}].default.http.hostSelection[${j}].updateFrequency` });
          });
          // check for duplicate OmitPreviousPriorities
          const opp = d.http.hostSelection.filter(hs => hs.predicate === 'OmitPreviousPriorities');
          if (opp.length > 1)
            errors.push({ msg: 'OmitPreviousPriorities can only be specified once', path: `${prefix}[${i}].default.http.hostSelection` });
        }
        // retryOn validation
        if (Array.isArray(d.http?.retryOn)) {
          const validRetryOn = [
            '5xx', '5XX', 'GatewayError', 'Reset', 'Retriable4xx', 'ConnectFailure',
            'EnvoyRatelimited', 'RefusedStream', 'Http3PostConnectFailure',
            'HttpMethodConnect', 'HttpMethodDelete', 'HttpMethodGet', 'HttpMethodHead',
            'HttpMethodOptions', 'HttpMethodPatch', 'HttpMethodPost', 'HttpMethodPut', 'HttpMethodTrace',
            'retriable_status_codes', 'retriable_headers',
          ];
          d.http.retryOn.forEach((val, j) => {
            const strVal = String(val);
            if (!validRetryOn.includes(strVal)) {
              const num = parseInt(strVal);
              if (isNaN(num) || num < 100 || num > 599)
                errors.push({ msg: `invalid retryOn value: ${strVal}`, path: `${prefix}[${i}].default.http.retryOn[${j}]` });
            }
          });
        }
      });
    };
    checkRetry(spec.to, 'spec.to');
  }

  // -- MeshHealthCheck specific --
  if (kind === 'MeshHealthCheck') {
    const checkHC = (items, prefix) => {
      if (!Array.isArray(items)) return;
      items.forEach((item, i) => {
        const d = item.default;
        if (!d || typeof d !== 'object') return;
        if (Object.keys(d).length === 0)
          errors.push({ msg: 'default must not be empty', path: `${prefix}[${i}].default` });
        // http path validation
        if (d.http?.path && !d.http.path.startsWith('/'))
          errors.push({ msg: 'path must start with /', path: `${prefix}[${i}].default.http.path` });
        // eventLogPath validation
        if (d.eventLogPath && !d.eventLogPath.match(/^[a-zA-Z0-9\/_\-\.]+$/))
          errors.push({ msg: 'invalid eventLogPath', path: `${prefix}[${i}].default.eventLogPath` });
        // negative thresholds
        if (d.unhealthyThreshold !== undefined && d.unhealthyThreshold < 1)
          errors.push({ msg: 'must be >= 1', path: `${prefix}[${i}].default.unhealthyThreshold` });
        if (d.healthyThreshold !== undefined && d.healthyThreshold < 1)
          errors.push({ msg: 'must be >= 1', path: `${prefix}[${i}].default.healthyThreshold` });
        // negative durations
        const durFields = ['interval', 'timeout', 'initialJitter', 'intervalJitter', 'noTrafficInterval'];
        for (const f of durFields) {
          if (typeof d[f] === 'string' && d[f].startsWith('-'))
            errors.push({ msg: 'must not be negative', path: `${prefix}[${i}].default.${f}` });
        }
        // percentage fields
        if (d.intervalJitterPercent !== undefined && (d.intervalJitterPercent < 0 || d.intervalJitterPercent > 100))
          errors.push({ msg: 'must be between 0 and 100', path: `${prefix}[${i}].default.intervalJitterPercent` });
        if (d.healthyPanicThreshold !== undefined) {
          const val = typeof d.healthyPanicThreshold === 'string' ? parseFloat(d.healthyPanicThreshold) : d.healthyPanicThreshold;
          if (!isNaN(val) && (val < 0 || val > 100))
            errors.push({ msg: 'must be between 0 and 100', path: `${prefix}[${i}].default.healthyPanicThreshold` });
        }
      });
    };
    checkHC(spec.to, 'spec.to');
  }

  // -- MeshTimeout specific --
  if (kind === 'MeshTimeout') {
    const checkTimeout = (items, prefix) => {
      if (!Array.isArray(items)) return;
      items.forEach((item, i) => {
        const d = item.default;
        if (!d || typeof d !== 'object') return;
        if (Object.keys(d).length === 0)
          errors.push({ msg: 'missing timeout configuration', path: `${prefix}[${i}].default` });
        // empty http section
        if (d.http && typeof d.http === 'object' && Object.keys(d.http).length === 0)
          errors.push({ msg: 'http must not be empty', path: `${prefix}[${i}].default.http` });
        // negative durations
        const checkDuration = (val, path) => {
          if (typeof val === 'string') {
            // Go duration: check for negative
            if (val.startsWith('-'))
              errors.push({ msg: 'timeout cannot be negative', path });
          }
        };
        if (d.connectionTimeout) checkDuration(d.connectionTimeout, `${prefix}[${i}].default.connectionTimeout`);
        if (d.idleTimeout) checkDuration(d.idleTimeout, `${prefix}[${i}].default.idleTimeout`);
        if (d.http?.requestTimeout) checkDuration(d.http.requestTimeout, `${prefix}[${i}].default.http.requestTimeout`);
        if (d.http?.streamIdleTimeout) checkDuration(d.http.streamIdleTimeout, `${prefix}[${i}].default.http.streamIdleTimeout`);
        if (d.http?.maxStreamDuration) checkDuration(d.http.maxStreamDuration, `${prefix}[${i}].default.http.maxStreamDuration`);
        if (d.http?.maxConnectionDuration) checkDuration(d.http.maxConnectionDuration, `${prefix}[${i}].default.http.maxConnectionDuration`);
        if (d.http?.requestHeadersTimeout) checkDuration(d.http.requestHeadersTimeout, `${prefix}[${i}].default.http.requestHeadersTimeout`);
      });
    };
    checkTimeout(spec.to, 'spec.to');
    checkTimeout(spec.from, 'spec.from');
    checkTimeout(spec.rules, 'spec.rules');
    // to[] targetRef sectionName not allowed for MeshHTTPRoute
    if (hasTo) {
      spec.to.forEach((item, i) => {
        if (item.targetRef?.kind === 'MeshHTTPRoute' && item.targetRef?.sectionName)
          errors.push({ msg: 'sectionName is not allowed for MeshHTTPRoute', path: `spec.to[${i}].targetRef.sectionName` });
      });
    }
    // targetRef labels+name mutual exclusivity for MeshExternalService in to[]
    if (hasTo) {
      spec.to.forEach((item, i) => {
        if (item.targetRef?.kind === 'MeshExternalService' && item.targetRef.labels && item.targetRef.name)
          errors.push({ msg: 'name and labels cannot be used together', path: `spec.to[${i}].targetRef` });
      });
    }
  }

  return errors;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { validateSemantic, TOP_TARGETREF_KINDS, TO_TARGETREF_KINDS, FROM_TARGETREF_KINDS };
}
