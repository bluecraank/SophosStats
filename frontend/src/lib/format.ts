const nf = new Intl.NumberFormat("de-DE");
const nf1 = new Intl.NumberFormat("de-DE", { maximumFractionDigits: 1 });

export const fmtNumber = (n: number | null | undefined) => (n == null ? "–" : nf.format(n));
export const fmtPercent = (n: number | null | undefined) => (n == null ? "–" : `${nf1.format(n)} %`);

const BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return "–";
  let i = 0;
  let v = n;
  while (v >= 1024 && i < BYTE_UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  return `${nf1.format(v)} ${BYTE_UNITS[i]}`;
}

const BIT_UNITS = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
export function fmtBps(n: number | null | undefined): string {
  if (n == null) return "–";
  let i = 0;
  let v = n;
  while (v >= 1000 && i < BIT_UNITS.length - 1) {
    v /= 1000;
    i++;
  }
  return `${nf1.format(v)} ${BIT_UNITS[i]}`;
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "–";
  return new Date(iso).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "medium" });
}

export function fmtAxisTime(iso: string, hours: number): string {
  const d = new Date(iso);
  return hours > 48
    ? d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" })
    : d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
}

const rtf = new Intl.RelativeTimeFormat("de-DE", { numeric: "auto" });
export function fmtRelative(iso: string | null | undefined): string {
  if (!iso) return "nie";
  const diff = (new Date(iso).getTime() - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 60) return rtf.format(Math.round(diff), "second");
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  return rtf.format(Math.round(diff / 86400), "day");
}

export function fmtUptime(ticks: number | undefined): string {
  if (ticks == null) return "–";
  const s = Math.floor(ticks / 100);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return d > 0 ? `${d} T ${h} h` : `${h} h ${m} min`;
}
