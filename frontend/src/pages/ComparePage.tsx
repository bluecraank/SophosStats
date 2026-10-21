import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Card, Empty, ErrorBox, Loading } from "../components/ui";
import { api } from "../lib/api";
import type { Firewall } from "../lib/types";
import { changedKeys } from "./firewall/ChangesTab";

interface TypeSummary {
  entity_type: string;
  only_a: number;
  only_b: number;
  different: number;
  same: number;
}
interface Detail {
  only_a: { name: string; data: unknown }[];
  only_b: { name: string; data: unknown }[];
  different: { name: string; a: unknown; b: unknown }[];
  same: number;
}

function Pre({ value }: { value: unknown }) {
  return <pre className="max-h-80 overflow-auto rounded border border-line bg-surface-2 p-2 text-xs">{JSON.stringify(value, null, 2)}</pre>;
}

export function ComparePage() {
  const firewalls = useQuery({ queryKey: ["firewalls"], queryFn: () => api<Firewall[]>("/api/firewalls") });
  const [a, setA] = useState<number | null>(null);
  const [b, setB] = useState<number | null>(null);
  const [type, setType] = useState<string | null>(null);
  const list = firewalls.data ?? [];
  const fa = a ?? list[0]?.id ?? null;
  const fb = b ?? list[1]?.id ?? null;
  const ready = fa != null && fb != null && fa !== fb;

  const summary = useQuery({
    queryKey: ["compare", fa, fb],
    queryFn: () => api<{ types: TypeSummary[] }>("/api/compare", { params: { a: fa, b: fb } }),
    enabled: ready,
  });
  const detail = useQuery({
    queryKey: ["compare", fa, fb, type],
    queryFn: () => api<Detail>("/api/compare", { params: { a: fa, b: fb, entity_type: type } }),
    enabled: ready && !!type,
  });
  const name = (id: number | null) => list.find((f) => f.id === id)?.name ?? "?";

  if (firewalls.isPending) return <Loading />;
  if (list.length < 2) return <Empty>Für einen Vergleich werden mindestens zwei Firewalls benötigt.</Empty>;

  const select = (value: number | null, set: (v: number) => void, label: string) => (
    <select className="input w-auto" value={value ?? ""} onChange={(e) => { set(Number(e.target.value)); setType(null); }} aria-label={label}>
      {list.map((f) => (
        <option key={f.id} value={f.id}>{f.name}</option>
      ))}
    </select>
  );

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Firewalls vergleichen</h1>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {select(fa, setA, "Firewall A")}
        <span className="text-ink-2">mit</span>
        {select(fb, setB, "Firewall B")}
      </div>
      {!ready && <Empty>Zwei verschiedene Firewalls auswählen</Empty>}
      <ErrorBox error={summary.error ?? detail.error} />
      {summary.data && (
        <Card title="Objekttypen">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-ink-2">
              <tr>
                <th className="py-1 font-medium">Typ</th>
                <th className="py-1 text-right font-medium">Nur {name(fa)}</th>
                <th className="py-1 text-right font-medium">Nur {name(fb)}</th>
                <th className="py-1 text-right font-medium">Unterschiedlich</th>
                <th className="py-1 text-right font-medium">Gleich</th>
              </tr>
            </thead>
            <tbody>
              {summary.data.types.map((t) => (
                <tr
                  key={t.entity_type}
                  onClick={() => setType(t.entity_type)}
                  className={`cursor-pointer border-t border-line hover:bg-surface-2 ${type === t.entity_type ? "bg-accent/12" : ""}`}
                >
                  <td className="py-1.5 font-medium">{t.entity_type}</td>
                  <td className="py-1.5 text-right">{t.only_a || "–"}</td>
                  <td className="py-1.5 text-right">{t.only_b || "–"}</td>
                  <td className="py-1.5 text-right">{t.different || "–"}</td>
                  <td className="py-1.5 text-right text-ink-2">{t.same}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
      {type && detail.isPending && <Loading />}
      {type && detail.data && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title={`Nur auf ${name(fa)} (${detail.data.only_a.length})`}>
            <ul className="space-y-1 text-sm">{detail.data.only_a.map((o) => <li key={o.name}>{o.name}</li>)}</ul>
          </Card>
          <Card title={`Nur auf ${name(fb)} (${detail.data.only_b.length})`}>
            <ul className="space-y-1 text-sm">{detail.data.only_b.map((o) => <li key={o.name}>{o.name}</li>)}</ul>
          </Card>
          <Card title={`Unterschiedlich (${detail.data.different.length})`} className="lg:col-span-2">
            <div className="space-y-2">
              {detail.data.different.map((d) => (
                <details key={d.name} className="rounded-md border border-line">
                  <summary className="cursor-pointer px-3 py-2 text-sm">
                    <span className="font-medium">{d.name}</span>{" "}
                    <span className="text-xs text-ink-2">– {changedKeys(d.a, d.b).join(", ")}</span>
                  </summary>
                  <div className="grid gap-3 border-t border-line p-3 md:grid-cols-2">
                    <div><div className="mb-1 text-xs text-ink-2">{name(fa)}</div><Pre value={d.a} /></div>
                    <div><div className="mb-1 text-xs text-ink-2">{name(fb)}</div><Pre value={d.b} /></div>
                  </div>
                </details>
              ))}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
