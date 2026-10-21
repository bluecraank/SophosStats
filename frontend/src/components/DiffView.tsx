import { diffLines, diffWordsWithSpace } from "diff";
import { ChevronsUpDown } from "lucide-react";
import { Fragment, useMemo, useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";

/** JSON mit sortierten Schlüsseln – eine andere Feldreihenfolge soll nicht als Änderung erscheinen. */
function stableJson(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === "object") {
      return Object.fromEntries(
        Object.keys(v as object)
          .sort()
          .map((k) => [k, sort((v as Record<string, unknown>)[k])]),
      );
    }
    return v;
  };
  return value == null ? "" : JSON.stringify(sort(value), null, 2);
}

type Side = { no: number; text: string } | null;
interface Row {
  kind: "same" | "changed" | "removed" | "added";
  left: Side;
  right: Side;
}

function splitLines(value: string): string[] {
  const lines = value.split("\n");
  if (lines.at(-1) === "") lines.pop();
  return lines;
}

/** Zeilen-Diff, ausgerichtet: entfernte und hinzugefügte Blöcke werden zeilenweise gegenübergestellt. */
function buildRows(oldText: string, newText: string): Row[] {
  const rows: Row[] = [];
  let l = 0;
  let r = 0;
  const parts = diffLines(oldText, newText);
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const lines = splitLines(part.value);
    if (!part.added && !part.removed) {
      for (const text of lines) rows.push({ kind: "same", left: { no: ++l, text }, right: { no: ++r, text } });
      continue;
    }
    if (part.removed && parts[i + 1]?.added) {
      const added = splitLines(parts[i + 1].value);
      for (let k = 0; k < Math.max(lines.length, added.length); k++) {
        const left = k < lines.length ? { no: ++l, text: lines[k] } : null;
        const right = k < added.length ? { no: ++r, text: added[k] } : null;
        rows.push({ kind: left && right ? "changed" : left ? "removed" : "added", left, right });
      }
      i++;
      continue;
    }
    for (const text of lines) {
      rows.push(
        part.removed
          ? { kind: "removed", left: { no: ++l, text }, right: null }
          : { kind: "added", left: null, right: { no: ++r, text } },
      );
    }
  }
  return rows;
}

/** Innerhalb einer geänderten Zeile die tatsächlich geänderten Wörter/Werte markieren. */
function inline(left: string, right: string): [ReactNode, ReactNode] {
  const parts = diffWordsWithSpace(left, right);
  const l: ReactNode[] = [];
  const r: ReactNode[] = [];
  parts.forEach((p, i) => {
    if (p.removed) l.push(<mark key={i} className="rounded-sm bg-critical/35 text-inherit">{p.value}</mark>);
    else if (p.added) r.push(<mark key={i} className="rounded-sm bg-good/35 text-inherit">{p.value}</mark>);
    else {
      l.push(p.value);
      r.push(p.value);
    }
  });
  return [l, r];
}

const CONTEXT = 3;

type Block = { type: "rows"; rows: Row[] } | { type: "fold"; rows: Row[]; id: number };

/** Lange unveränderte Abschnitte einklappen, mit etwas Kontext um jede Änderung. */
function fold(rows: Row[]): Block[] {
  const blocks: Block[] = [];
  let i = 0;
  let foldId = 0;
  while (i < rows.length) {
    if (rows[i].kind !== "same") {
      const start = i;
      while (i < rows.length && rows[i].kind !== "same") i++;
      blocks.push({ type: "rows", rows: rows.slice(start, i) });
      continue;
    }
    const start = i;
    while (i < rows.length && rows[i].kind === "same") i++;
    const run = rows.slice(start, i);
    const head = start === 0 ? 0 : CONTEXT;
    const tail = i === rows.length ? 0 : CONTEXT;
    if (run.length <= head + tail + 2) {
      blocks.push({ type: "rows", rows: run });
    } else {
      if (head) blocks.push({ type: "rows", rows: run.slice(0, head) });
      blocks.push({ type: "fold", rows: run.slice(head, run.length - tail), id: foldId++ });
      if (tail) blocks.push({ type: "rows", rows: run.slice(run.length - tail) });
    }
  }
  return blocks;
}

const LEFT_BG = { same: "", changed: "bg-critical/10", removed: "bg-critical/15", added: "bg-muted/40" };
const RIGHT_BG = { same: "", changed: "bg-good/10", removed: "bg-muted/40", added: "bg-good/15" };
function DiffRow({ row }: { row: Row }) {
  const [l, r] =
    row.kind === "changed" && row.left && row.right ? inline(row.left.text, row.right.text) : [row.left?.text, row.right?.text];
  const num = "select-none border-r px-2 text-right text-muted-foreground/60";
  const marker = "mr-1.5 inline-block w-2 select-none text-muted-foreground/70";
  return (
    <tr className="align-top">
      <td className={cn(num, LEFT_BG[row.kind])}>{row.left?.no}</td>
      <td className={cn("px-2 whitespace-pre-wrap break-all", LEFT_BG[row.kind])}>
        {row.left && (
          <>
            <span className={marker}>{row.kind === "removed" || row.kind === "changed" ? "−" : ""}</span>
            {l}
          </>
        )}
      </td>
      <td className={cn(num, "border-l", RIGHT_BG[row.kind])}>{row.right?.no}</td>
      <td className={cn("px-2 whitespace-pre-wrap break-all", RIGHT_BG[row.kind])}>
        {row.right && (
          <>
            <span className={marker}>{row.kind === "added" || row.kind === "changed" ? "+" : ""}</span>
            {r}
          </>
        )}
      </td>
    </tr>
  );
}

/**
 * Side-by-Side-Vergleich zweier JSON-Werte in einer gemeinsamen Scrollfläche: Zeilen sind ausgerichtet,
 * Entferntes links rot, Hinzugefügtes rechts grün, geänderte Werte innerhalb der Zeile markiert.
 */
export function DiffView({
  left,
  right,
  leftTitle = "Vorher",
  rightTitle = "Nachher",
  maxHeight = "28rem",
}: {
  left: unknown;
  right: unknown;
  leftTitle?: string;
  rightTitle?: string;
  maxHeight?: string;
}) {
  const rows = useMemo(() => buildRows(stableJson(left), stableJson(right)), [left, right]);
  const blocks = useMemo(() => fold(rows), [rows]);
  const [open, setOpen] = useState<Set<number>>(new Set());
  const changed = rows.filter((r) => r.kind !== "same").length;

  return (
    <div className="overflow-hidden rounded-lg border bg-card">
      <div className="overflow-auto font-mono text-xs leading-5" style={{ maxHeight }}>
        <table className="w-full table-fixed border-collapse">
          <colgroup>
            <col className="w-10" />
            <col />
            <col className="w-10" />
            <col />
          </colgroup>
          <thead className="sticky top-0 z-10 bg-muted/95 font-sans text-xs backdrop-blur">
            <tr>
              <th colSpan={2} className="border-b px-3 py-1.5 text-left font-medium">
                {leftTitle}
              </th>
              <th colSpan={2} className="border-b border-l px-3 py-1.5 text-left font-medium">
                {rightTitle}
                <span className="ml-2 font-normal text-muted-foreground">{changed} Zeile(n) unterschiedlich</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {blocks.map((b, i) =>
              b.type === "rows" || open.has(b.id) ? (
                <Fragment key={i}>
                  {b.rows.map((row, j) => (
                    <DiffRow key={j} row={row} />
                  ))}
                </Fragment>
              ) : (
                <tr key={i}>
                  <td colSpan={4} className="border-y bg-muted/40 p-0">
                    <button
                      type="button"
                      onClick={() => setOpen(new Set(open).add(b.id))}
                      className="flex w-full items-center justify-center gap-1.5 py-1 font-sans text-xs text-muted-foreground hover:bg-muted hover:text-foreground"
                    >
                      <ChevronsUpDown className="size-3.5" />
                      {b.rows.length} unveränderte Zeilen anzeigen
                    </button>
                  </td>
                </tr>
              ),
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
