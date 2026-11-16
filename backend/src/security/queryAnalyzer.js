import { parse, Kind } from 'graphql';
import { config } from './config.js';

const AUTH_FIELDS = new Set(['login', 'signup']);
const FIELD_BUDGET = 5000; // stop walking absurdly large queries (fragment bombs)

// Static analysis: we read the query's structure WITHOUT executing it.
export function analyzeQuery(queryText) {
  let doc;
  try {
    doc = parse(queryText);
  } catch {
    return { malformed: true };
  }

  const fragments = new Map();
  const operations = [];
  for (const def of doc.definitions) {
    if (def.kind === Kind.FRAGMENT_DEFINITION) fragments.set(def.name.value, def);
    else if (def.kind === Kind.OPERATION_DEFINITION) operations.push(def);
  }

  const r = { malformed: false, depth: 0, cost: 0, fields: 0, aliases: 0, authOps: 0, budgetExceeded: false };
  const rootFields = []; // names of the top-level fields (used to spot introspection)

  // How many rows does this list field return? Used as a cost multiplier.
  function listMultiplier(field) {
    const name = field.name.value;
    if (name === 'feed') {
      const arg = field.arguments.find((a) => a.name.value === 'limit');
      if (arg?.value.kind === Kind.INT) {
        return Math.min(Math.max(parseInt(arg.value.value, 10), 1), config.maxPageSize);
      }
      if (arg) return config.maxPageSize; // a variable: assume the worst
    }
    return config.listSize[name] ?? 1;
  }

  function walk(selectionSet, level, multiplier, stack) {
    for (const sel of selectionSet.selections) {
      if (r.fields > FIELD_BUDGET) {
        r.budgetExceeded = true;
        return;
      }
      if (sel.kind === Kind.FIELD) {
        r.fields++;
        if (level === 1) rootFields.push(sel.name.value);
        r.cost += multiplier;
        r.depth = Math.max(r.depth, level);
        if (sel.alias) r.aliases++;
        if (AUTH_FIELDS.has(sel.name.value)) r.authOps++;
        if (sel.selectionSet) walk(sel.selectionSet, level + 1, multiplier * listMultiplier(sel), stack);
      } else if (sel.kind === Kind.INLINE_FRAGMENT) {
        walk(sel.selectionSet, level, multiplier, stack);
      } else if (sel.kind === Kind.FRAGMENT_SPREAD) {
        // Attackers hide depth inside fragments, so we expand them (guarding against cycles)
        const name = sel.name.value;
        const frag = fragments.get(name);
        if (!frag || stack.has(name)) continue;
        stack.add(name);
        walk(frag.selectionSet, level, multiplier, stack);
        stack.delete(name);
      }
    }
  }

  for (const op of operations) walk(op.selectionSet, 1, 1, new Set());
  // introspection-only = every top-level field is __schema / __type
  r.introspection = rootFields.length > 0 && rootFields.every((n) => n === '__schema' || n === '__type');
  return r;
}
