/** A bounded, duplicate-key-rejecting JSON parser for security-sensitive imports. */

export class StrictJsonError extends Error {}

export function parseStrictJson(source: string, maxDepth = 128): unknown {
  let cursor = 0;
  const whitespace = (): void => { while ([" ", "\t", "\n", "\r"].includes(source[cursor] ?? "")) cursor += 1; };
  const fail = (): never => { throw new StrictJsonError("invalid JSON"); };
  const string = (): string => {
    if (source[cursor++] !== '"') fail();
    let output = "";
    while (cursor < source.length) {
      const character = source[cursor++]!;
      if (character === '"') return output;
      if (character === "\\") {
        const escape = source[cursor++] ?? fail();
        if (escape === "u") {
          const hex = source.slice(cursor, cursor + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail();
          output += String.fromCharCode(Number.parseInt(hex, 16));
          cursor += 4;
        } else {
          const escapes: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
          if (!(escape in escapes)) fail();
          output += escapes[escape];
        }
      } else {
        if (character.charCodeAt(0) < 0x20) fail();
        output += character;
      }
    }
    return fail();
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
