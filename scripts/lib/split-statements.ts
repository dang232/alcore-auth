/**
 * Split a migration script into statements. A semicolon inside a dollar-quoted
 * body ($$ or $tag$), a quoted literal, a quoted identifier or a line comment
 * never splits: a function body or a trigger definition has to reach
 * PostgreSQL whole, and a half statement fails the whole migration.
 */
export function splitStatements(raw: string): string[] {
  const statements: string[] = [];
  let current = "";
  let dollarTag: string | null = null;
  let inSingle = false;
  let inDouble = false;
  let inLineComment = false;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i] as string;
    const rest = raw.slice(i);
    if (inLineComment) {
      if (ch === "\n") {
        inLineComment = false;
        current += ch;
      }
      continue;
    }
    if (dollarTag !== null) {
      if (rest.startsWith(dollarTag)) {
        current += dollarTag;
        i += dollarTag.length - 1;
        dollarTag = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (inSingle) {
      current += ch;
      if (ch === "'") {
        if (raw[i + 1] === "'") {
          current += "'";
          i += 1;
        } else {
          inSingle = false;
        }
      }
      continue;
    }
    if (inDouble) {
      current += ch;
      if (ch === '"') inDouble = false;
      continue;
    }
    if (ch === "-" && raw[i + 1] === "-") {
      inLineComment = true;
      i += 1;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      current += ch;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      current += ch;
      continue;
    }
    if (ch === "$") {
      const tag = /^(\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$)/.exec(rest);
      if (tag !== null) {
        dollarTag = tag[1] as string;
        current += dollarTag;
        i += dollarTag.length - 1;
        continue;
      }
    }
    if (ch === ";") {
      const statement = current.trim();
      if (statement !== "") statements.push(statement);
      current = "";
      continue;
    }
    current += ch;
  }
  const tail = current.trim();
  if (tail !== "") statements.push(tail);
  return statements;
}
