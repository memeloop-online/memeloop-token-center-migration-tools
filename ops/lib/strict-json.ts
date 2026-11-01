/** A bounded, duplicate-key-rejecting JSON parser for security-sensitive imports. */

export class StrictJsonError extends Error {}

export function parseStrictJson(source: string, maxDepth = 128): unknown {
  let cursor = 0;
  const whitespace = (): void => { while ([" ", "\t", "\n", "\r"].includes(source[cursor] ?? "")) cursor += 1; };
  const fail = (): never => { throw new StrictJsonError("invalid JSON"); };
  const stringBoundary = /["\\\u0000-\u001f]/g;
  const string = (): string => {
    const start = cursor;
    if (source[cursor++] !== '"') fail();
    let escaped = false;
    stringBoundary.lastIndex = cursor;
    for (;;) {
      const boundary = stringBoundary.exec(source);
      if (boundary === null) return fail();
      cursor = stringBoundary.lastIndex;
      if (boundary[0] === '"') {
        if (!escaped) return source.slice(start + 1, cursor - 1);
        try { return JSON.parse(source.slice(start, cursor)) as string; } catch { return fail(); }
      }
      if (boundary[0] !== "\\") return fail();
      escaped = true;
      stringBoundary.lastIndex = cursor + 1;
    }
  };
  const value = (depth: number): unknown => {
    if (depth > maxDepth) fail();
    whitespace();
    const head = source[cursor];
    if (head === '"') return string();
    if (head === "{") {
      cursor += 1;
      const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const keys = new Set<string>();
      whitespace();
      if (source[cursor] === "}") { cursor += 1; return output; }
      while (true) {
        whitespace();
        if (source[cursor] !== '"') fail();
        const key = string();
        if (keys.has(key)) throw new StrictJsonError("duplicate JSON object key");
        keys.add(key);
        whitespace();
        if (source[cursor++] !== ":") fail();
        output[key] = value(depth + 1);
        whitespace();
        const separator = source[cursor++];
        if (separator === "}") return output;
        if (separator !== ",") fail();
      }
    }
    if (head === "[") {
      cursor += 1;
      const output: unknown[] = [];
      whitespace();
      if (source[cursor] === "]") { cursor += 1; return output; }
      while (true) {
        output.push(value(depth + 1));
        whitespace();
        const separator = source[cursor++];
        if (separator === "]") return output;
        if (separator !== ",") fail();
      }
    }
    for (const [literal, result] of [["true", true], ["false", false], ["null", null]] as const) {
      if (source.startsWith(literal, cursor)) { cursor += literal.length; return result; }
    }
    const match = source.slice(cursor).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (match === null) return fail();
    cursor += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number) || (!/[.eE]/.test(match[0]) && !Number.isSafeInteger(number))) fail();
    return number;
  };
  const output = value(0);
  whitespace();
  if (cursor !== source.length) fail();
  return output;
}
