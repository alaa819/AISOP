import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import {
  ApiRequestError, getApiErrorMessage, isBackendUnavailable, subscribeUnauthorized,
  login, logout, hasAccessToken, getCurrentUser,
  type CurrentUser,
  getStatistics,
  getAlerts,
  type Alert,
  type AlertsResponse,
} from "./services/api";

type DataStatus = "loading" | "success" | "empty" | "error";
type SectionState = { status: DataStatus; refreshing: boolean; error: string | null; updatedAt: number | null };
const initialSectionState: SectionState = { status: "loading", refreshing: false, error: null, updatedAt: null };

function DataSectionStatus({ label, state, hasData, onRetry, retryAllowed = true }: { label: string; state: SectionState; hasData: boolean; onRetry: () => void; retryAllowed?: boolean }) {
  const stale = state.status === "error" && hasData;
  if (state.status === "success" && !state.refreshing) return null;
  if (state.status === "empty" && !state.refreshing) return label === "Statistics" ? <div className="overview-status" data-section="statistics" data-state="empty" role="status">Statistics: No alerts recorded.</div> : null;
  return <div className="overview-status" data-section={label.toLowerCase()} data-state={state.status} role={state.status === "error" ? "alert" : "status"} style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
    {state.refreshing && <span className="loading-spinner"/>}
    <span><strong>{label}: </strong>{state.status === "error" ? <>{stale ? "Stale data — showing the last successful results. " : "Data unavailable. "}{state.error}{stale && state.updatedAt !== null && <> Last updated {new Date(state.updatedAt).toLocaleTimeString()}.</>}{state.refreshing && " Retrying…"}</> : hasData ? "Updating…" : "Loading…"}</span>
    {state.status === "error" && retryAllowed && <Button onClick={onRetry} disabled={state.refreshing}>Retry {label}</Button>}
  </div>;
}

type Severity = "High" | "Medium" | "Low" | "Informational";
type Page = "Overview" | "Events & Alerts" | "Investigations" | "Linux Hosts" | "Logs" | "Detection Rules" | "Reports" | "Settings";
function getPermissions(role: CurrentUser["role"]) {
  const isAdmin = role.toUpperCase() === "ADMIN";
  const isAnalyst = role.toUpperCase() === "ANALYST";
  return {
    canAccessSettings: isAdmin,
    canEditInvestigations: isAdmin || isAnalyst,
    canManageRules: isAdmin,
    canViewStatistics: isAdmin || isAnalyst,
  };
}
function canAccessPage(page: Page, permissions: ReturnType<typeof getPermissions>) {
  return page !== "Settings" || permissions.canAccessSettings;
}

type Event = { id: string; time: string; severity: Severity; title: string; host: string; source: string; status: string; user: string; ip: string; process: string; raw: string };
type Host = { name: string; ip: string; os: string; alerts: number; severity: Severity; last: string; status: string; cpu: number; memory: number };
type Investigation = { id: string; name: string; severity: Severity; host: string; status: string; analyst: string; created: string; updated: string; summary: string };

const hosts: Host[] = [
  { name: "prod-web-01", ip: "10.0.4.21", os: "Ubuntu 22.04 LTS", alerts: 18, severity: "High", last: "2 min ago", status: "At risk", cpu: 72, memory: 64 },
  { name: "db-primary-02", ip: "10.0.12.18", os: "Debian 12", alerts: 12, severity: "High", last: "4 min ago", status: "At risk", cpu: 48, memory: 81 },
  { name: "edge-gateway-01", ip: "10.0.2.14", os: "Ubuntu 24.04 LTS", alerts: 9, severity: "Medium", last: "1 min ago", status: "Monitoring", cpu: 36, memory: 42 },
  { name: "staging-api-03", ip: "10.0.8.31", os: "Rocky Linux 9", alerts: 4, severity: "Low", last: "6 min ago", status: "Healthy", cpu: 22, memory: 39 },
  { name: "worker-node-04", ip: "10.0.16.44", os: "Ubuntu 22.04 LTS", alerts: 2, severity: "Low", last: "3 min ago", status: "Healthy", cpu: 56, memory: 53 },
];
const investigations: Investigation[] = [
  { id: "INV-1042", name: "Potential SSH brute force & access", severity: "High", host: "prod-web-01", status: "Investigating", analyst: "Sarah Chen", created: "Today, 14:34", updated: "2 min ago", summary: "Repeated failed SSH authentication attempts were followed by a successful root login from the same external IP. Validate access and review subsequent process activity." },
  { id: "INV-1041", name: "Unexpected privilege escalation", severity: "High", host: "db-primary-02", status: "Open", analyst: "Marcus Lee", created: "Today, 14:30", updated: "12 min ago", summary: "A service account executed a privileged shell on the primary database host. Confirm whether this was part of an approved deployment." },
  { id: "INV-1040", name: "Unusual outbound process activity", severity: "High", host: "prod-web-01", status: "Open", analyst: "Unassigned", created: "Today, 14:23", updated: "19 min ago", summary: "An unexpected process made an outbound request from a production web host. Review command execution and network context." },
  { id: "INV-1039", name: "Gateway firewall rule modification", severity: "Medium", host: "edge-gateway-01", status: "Investigating", analyst: "Priya Patel", created: "Today, 14:01", updated: "38 min ago", summary: "An inbound firewall rule was added on the edge gateway. Check the change record and confirm the approved exposure." },
  { id: "INV-1038", name: "Service account creation review", severity: "Low", host: "staging-api-03", status: "Resolved", analyst: "Marcus Lee", created: "Yesterday, 16:12", updated: "Yesterday", summary: "A new service user was created during a scheduled staging maintenance window." },
];
type Rule = { name: string; description: string; severity: Severity; enabled: boolean; source: string; last: string; count: number };
const initialRules: Rule[] = [
  { name: "SSH brute force attempt", description: "Repeated failed SSH logins from a single source", severity: "High", enabled: true, source: "auth.log", last: "2 min ago", count: 148 },
  { name: "Successful login after failures", description: "Successful authentication following multiple failures", severity: "High", enabled: true, source: "auth.log", last: "14 min ago", count: 23 },
  { name: "Privileged shell execution", description: "Unexpected sudo session or privileged shell", severity: "High", enabled: true, source: "auditd", last: "18 min ago", count: 37 },
  { name: "Firewall configuration change", description: "Changes to host firewall rules or policies", severity: "Medium", enabled: true, source: "syslog", last: "42 min ago", count: 19 },
  { name: "New local user", description: "Creation of a new local system account", severity: "Low", enabled: false, source: "auth.log", last: "Yesterday", count: 8 },
];

const nav: { label: Page; icon: string }[] = [
  { label: "Overview", icon: "grid" }, { label: "Events & Alerts", icon: "activity" }, { label: "Investigations", icon: "search-file" }, { label: "Linux Hosts", icon: "server" },
  { label: "Logs", icon: "terminal" }, { label: "Detection Rules", icon: "shield" }, { label: "Reports", icon: "chart" }, { label: "Settings", icon: "settings" },
];
const paths: Record<string, ReactNode> = {
  grid: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
  activity: <><path d="M3 12h4l3-7 4 14 3-7h4"/></>,
  "search-file": <><path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h8"/><path d="M13 3v5h5"/><circle cx="16" cy="16" r="3"/><path d="m18.2 18.2 2.3 2.3"/></>,
  server: <><rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M7 7h.01M7 17h.01M11 7h6M11 17h6"/></>,
  terminal: <><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/></>,
  shield: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></>,
  chart: <><path d="M3 3v18h18M7 16v-4m5 4V7m5 9v-6"/></>,
  settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2 2-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6V21h-2.8v-.8a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1-2-2 .1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.6-1H5v-2.8h.8a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L7 8.2l2-2 .1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.6V4h2.8v.8a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1 2 2-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.8v2.8H21a1.7 1.7 0 0 0-1.6 1Z"/></>,
  search: <><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/></>,
  bell: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/></>,
  refresh: <><path d="M20 11a8 8 0 0 0-14-5L4 8m0-5v5h5M4 13a8 8 0 0 0 14 5l2-2m0 5v-5h-5"/></>,
  chevron: <path d="m9 18 6-6-6-6"/>, down: <path d="m6 9 6 6 6-6"/>, close: <path d="M18 6 6 18M6 6l12 12"/>,
  arrow: <path d="M5 12h14m-6-6 6 6-6 6"/>, plus: <path d="M12 5v14M5 12h14"/>, download: <><path d="M12 3v12m-4-4 4 4 4-4M4 17v3h16v-3"/></>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>, filter: <><path d="M4 7h16M7 12h10m-7 5h4"/><circle cx="8" cy="7" r="2"/><circle cx="15" cy="12" r="2"/></>,
  check: <path d="m5 12 4 4L19 6"/>, external: <><path d="M13 5h6v6m0-6-9 9"/><path d="M19 14v5H5V5h5"/></>,
  sun: <><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></>,
  moon: <path d="M20.5 14.1A8.5 8.5 0 0 1 9.9 3.5a8.5 8.5 0 1 0 10.6 10.6Z"/>,
  user: <><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></>,
  logout: <><path d="M10 5H5v14h5M14 8l4 4-4 4m4-4H9"/></>,
  eye: <><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/></>,
  "eye-off": <><path d="m3 3 18 18M10.6 6.2A9.8 9.8 0 0 1 12 6c6 0 9.5 6 9.5 6a16 16 0 0 1-2.2 2.8M6.1 6.1C3.8 7.7 2.5 12 2.5 12s3.5 6 9.5 6a9 9 0 0 0 3.2-.6M10.3 10.3a2.5 2.5 0 0 0 3.4 3.4"/></>,
  lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></>,
};
function Icon({ name, size = 18, className = "" }: { name: string; size?: number; className?: string }) { return <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>; }
function Button({ children, icon, variant = "secondary", onClick, className = "", disabled = false, title }: { children?: ReactNode; icon?: string; variant?: "primary" | "secondary" | "ghost"; onClick?: () => void; className?: string; disabled?: boolean; title?: string }) { return <button type="button" title={title} disabled={disabled} onClick={onClick} className={`btn btn-${variant} ${className}`}>{icon && <Icon name={icon} size={16}/ >}{children}</button>; }
function Badge({ children, type = "neutral" }: { children: ReactNode; type?: string }) { return <span className={`badge badge-${type.toLowerCase().replace(/ /g, "-")}`}><span className="badge-dot"/>{children}</span>; }
function SearchField({ value, onChange, placeholder = "Search...", className = "" }: { value: string; onChange: (value: string) => void; placeholder?: string; className?: string }) { return <label className={`search-field ${className}`}><Icon name="search" size={16}/><input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} aria-label={placeholder}/>{value && <button type="button" className="clear-search" onClick={() => onChange("")} aria-label="Clear search"><Icon name="close" size={13}/></button>}</label>; }
function SelectField({ value, onChange, options, label }: { value: string; onChange: (value: string) => void; options: string[]; label: string }) { return <label className="select-wrap"><span className="sr-only">{label}</span><select value={value} onChange={e => onChange(e.target.value)} aria-label={label}>{options.map(o => <option key={o}>{o}</option>)}</select><Icon name="down" size={14}/></label>; }
function SectionHeading({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) { return <div className="section-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div>; }
function EmptyState({ title = "No results found", description = "Try adjusting your search or filters.", onReset }: { title?: string; description?: string; onReset?: () => void }) { return <div className="empty-state"><span className="empty-icon"><Icon name="search" size={22}/></span><strong>{title}</strong><p>{description}</p>{onReset && <Button onClick={onReset}>Clear filters</Button>}</div>; }
function DataTable<T>({ columns, rows, onRow, empty, rowKey }: { columns: { label: string; render: (row: T) => ReactNode; className?: string }[]; rows: T[]; onRow?: (row: T) => void; empty?: ReactNode; rowKey: (row: T) => string }) { return <div className="table-scroll"><table><thead><tr>{columns.map(c => <th key={c.label} className={c.className}>{c.label}</th>)}</tr></thead><tbody>{rows.map(row => <tr key={rowKey(row)} className={onRow ? "interactive-row" : ""} onClick={() => onRow?.(row)} onKeyDown={e => { if (onRow && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); onRow(row); } }} tabIndex={onRow ? 0 : undefined}>{columns.map(c => <td key={c.label} className={c.className}>{c.render(row)}</td>)}</tr>)}</tbody></table>{rows.length === 0 && (empty || <EmptyState/>)}</div>; }
function Panel({ children, className = "" }: { children: ReactNode; className?: string }) { return <section className={`panel ${className}`}>{children}</section>; }
function StatCard({ label, value, change, tone, icon, onClick }: { label: string; value: string; change: string; tone?: string; icon: string; onClick: () => void }) { return <button type="button" className="stat-card" onClick={onClick}><span className="stat-top"><span>{label}</span><Icon name={icon} size={17}/></span><span className="stat-number">{value}</span><span className="stat-bottom"><span className={`stat-change ${tone || ""}`}>{change}</span><span>vs. previous 24h</span></span></button>; }
const series: Record<string, number[]> = {
  High: [5,6,5,7,6,6,7,8,9,11,13,15,18,21,25,29,23,17,22,27,34,29,21,15,11,9,8,7,6,6,5,6],
  Medium: [27,29,28,30,29,30,32,34,36,39,41,44,48,51,55,52,47,42,46,50,56,53,47,40,36,33,30,29,28,27,28,29],
  Low: [72,70,74,71,73,76,78,79,81,84,86,89,91,93,95,92,89,86,88,91,94,91,87,83,80,77,74,72,71,70,72,73],
};
const chartColors: Record<string, string> = { High: "#e6a36c", Medium: "#d9bd77", Low: "#698b9d" };
function ActivityChart() {
  const [visible, setVisible] = useState<string[]>(Object.keys(series));
  const [frame, setFrame] = useState(0);
  const [selected, setSelected] = useState(17);
  useEffect(() => {
    const ticker = window.setInterval(() => {
      setFrame(previous => (previous + 1) % 32);
    }, 2000);
    return () => { window.clearInterval(ticker); };
  }, []);
  const samples = (severity: string) => Array.from({ length: 24 }, (_, i) => (series[severity]?.[(frame + i) % 32] ?? 0));
  const pointX = (i: number) => (i / 23) * 960;
  const pointY = (value: number) => 158 - value * 1.42;
  const line = (values: number[]) => values.map((value, i) => `${pointX(i)},${pointY(value)}`).join(" ");
  const selectPoint = (clientX: number, bounds: DOMRect) => setSelected(Math.max(0, Math.min(23, Math.round(((clientX - bounds.left) / bounds.width) * 23))));
  const timeAt = (index: number) => new Date(2024, 0, 1, 13, 58 + (index + frame) * 2).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  return <div className="telemetry">
    <div className="telemetry-status"><strong>DEMO DATA</strong><span>Historical activity visualization · live time-series API not connected yet</span></div>
    <div className="chart-wrap"><div className="chart-y"><span>100</span><span>75</span><span>50</span><span>25</span><span>0</span></div><div className="chart-main">
      <svg viewBox="0 0 960 170" preserveAspectRatio="none" role="slider" tabIndex={0} aria-label="Security activity timeline. Use left and right arrow keys to inspect a point." aria-valuemin={0} aria-valuemax={23} aria-valuenow={selected} aria-valuetext={`${timeAt(selected)}: ${Object.keys(series).map(s => `${s} ${samples(s)[selected]}`).join(", ")}`} onPointerMove={e => selectPoint(e.clientX, e.currentTarget.getBoundingClientRect())} onKeyDown={e => { if (e.key === "ArrowRight") { e.preventDefault(); setSelected(i => Math.min(23, i + 1)); } if (e.key === "ArrowLeft") { e.preventDefault(); setSelected(i => Math.max(0, i - 1)); } }}>
        {[16,51,87,122,158].map(y => <line key={y} x1="0" x2="960" y1={y} y2={y} className="grid-line"/>)}
        <line x1={pointX(selected)} x2={pointX(selected)} y1="9" y2="158" className="selected-line"/>
        {visible.map(s => <polyline key={s} points={line(samples(s))} fill="none" stroke={chartColors[s]} strokeWidth="1.8" vectorEffect="non-scaling-stroke" strokeLinejoin="round" strokeLinecap="round" className="telemetry-line"/>)}
        {visible.map(s => <circle key={s} cx={pointX(selected)} cy={pointY(samples(s)[selected] ?? 0)} r="3.5" fill={chartColors[s]} stroke="var(--surface)" strokeWidth="1.5"/>)}
      </svg>
      <div className="chart-tooltip" style={{ left: `${Math.max(15, Math.min(85, selected / 23 * 100))}%` }}><strong>{timeAt(selected)}</strong>{Object.keys(series).map(s => <div key={s} className={!visible.includes(s) ? "hidden-severity" : ""}><span><i style={{ background: chartColors[s] }}/>{s}</span><b>{samples(s)[selected]}</b></div>)}</div>
      <div className="chart-x">{[0,4,8,12,16,20,23].map(index => <span key={index}>{timeAt(index)}</span>)}</div>
    </div></div>
    <div className="chart-legend" role="group" aria-label="Toggle severity lines">{Object.keys(series).map(s => <button type="button" key={s} aria-pressed={visible.includes(s)} onClick={() => setVisible(current => current.includes(s) ? current.filter(item => item !== s) : [...current, s])}><i style={{ background: chartColors[s] }}/>{s}</button>)}</div>
  </div>;
}
function SeverityChart({ statistics }: { statistics: { total_alerts: number; severity: { high: number; medium: number; low: number } } | null }) {
  const total = statistics?.total_alerts ?? 0;
  const data = [
    { label: "High", value: statistics?.severity.high ?? 0 },
    { label: "Medium", value: statistics?.severity.medium ?? 0 },
    { label: "Low", value: statistics?.severity.low ?? 0 },
  ].map(item => ({ ...item, pct: total > 0 ? (item.value / total) * 100 : 0 }));
  return <><div className="severity-total"><strong>{total}</strong><span>total alerts</span></div><div className="severity-stack">{data.map(d => <span key={d.label} style={{ width: `${d.pct}%`, background: chartColors[d.label] }} title={`${d.label}: ${d.value}`}/>)}</div><div className="severity-rows">{data.map(d => <div key={d.label}><span><i style={{ background: chartColors[d.label] }}/>{d.label}</span><strong>{d.value}</strong><span className="muted">{Math.round(d.pct)}%</span></div>)}</div></>;
}

function Dashboard({ currentUser, theme, toggleTheme, onLogout }: { currentUser: CurrentUser; theme: "dark" | "light"; toggleTheme: () => void; onLogout: (message?: string) => void }) {
  const permissions = getPermissions(currentUser.role);
  const { canAccessSettings, canEditInvestigations, canManageRules, canViewStatistics } = permissions;
  const initials = currentUser.username.split(/[\s._@-]+/).filter(Boolean).slice(0, 2).map(part => part[0]).join("").toUpperCase() || "U";
  const [page, setPage] = useState<Page>("Overview");
  const [search, setSearch] = useState(""); const [globalSearch, setGlobalSearch] = useState("");
  const [severity, updateSeverity] = useState("All severities");
  const [alertsPage, setAlertsPage] = useState(1);
  const alertsPageSize = 10;
  const setSeverity = (value: string) => { updateSeverity(value); setAlertsPage(1); }; const [hostFilter, setHostFilter] = useState("All hosts"); const [statusFilter, setStatusFilter] = useState("All statuses"); const [typeFilter, setTypeFilter] = useState("All event types"); const [sourceFilter, setSourceFilter] = useState("All sources"); const [userFilter, setUserFilter] = useState(""); const [processFilter, setProcessFilter] = useState("");
  const [timeRange, setTimeRange] = useState("Last 24 hours");
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null); const [selectedHost, setSelectedHost] = useState<Host | null>(null); const [selectedInvestigation, setSelectedInvestigation] = useState<Investigation | null>(null);
  const [expandedLog, setExpandedLog] = useState<string | null>(null); const [rules, setRules] = useState(initialRules); const [ruleModal, setRuleModal] = useState<Rule | "new" | null>(null); const [ruleName, setRuleName] = useState(""); const [ruleDescription, setRuleDescription] = useState(""); const [ruleSeverity, setRuleSeverity] = useState<Severity>("Medium");
  const [confirmation, setConfirmation] = useState<number | null>(null); const [notice, setNotice] = useState(""); const [showNotifications, setShowNotifications] = useState(false); const [showProfile, setShowProfile] = useState(false); const [showWorkspace, setShowWorkspace] = useState(false); const [mobileNav, setMobileNav] = useState(false); const [hostTab, setHostTab] = useState("Overview"); const [investigationStatus, setInvestigationStatus] = useState<Record<string,string>>({});
  useEffect(() => {
    if (!canAccessSettings) {
      setPage(previous => previous === "Settings" ? "Overview" : previous);
      setSelectedHost(null);
      setSelectedInvestigation(null);
    }
    if (!canManageRules) { setRuleModal(null); setConfirmation(null); }
  }, [canAccessSettings, canManageRules]);
  const [refreshing, setRefreshing] = useState(false);
  const [statistics, setStatistics] = useState<{
    total_alerts: number;
    severity: {
      high: number;
      medium: number;
      low: number;
    };
  } | null>(null);
  const [statisticsState, setStatisticsState] = useState<SectionState>(initialSectionState);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [alertsState, setAlertsState] = useState<SectionState & { key: string }>({ ...initialSectionState, key: "" });

  // Only Events & Alerts uses backend severity; other page filters remain local.
  const backendSeverity = page === "Events & Alerts" && severity !== "All severities" ? severity.toLowerCase() : undefined;
  const requestedOffset = page === "Events & Alerts" ? (alertsPage - 1) * alertsPageSize : 0;
  const alertsQueryKey = JSON.stringify([backendSeverity ?? "", requestedOffset]);
  const [alertsMetadata, setAlertsMetadata] = useState({ count: 0, limit: alertsPageSize, offset: 0, key: "", updatedAt: null as number | null });
  const reloadStatistics = useRef<() => Promise<boolean>>(async () => false);
  const reloadAlerts = useRef<() => Promise<boolean>>(async () => false);
  const hasCurrentAlerts = alertsMetadata.key === alertsQueryKey;
  const currentAlertsState: SectionState = alertsState.key === alertsQueryKey ? alertsState : { ...initialSectionState, refreshing: true };
  const statisticsLoading = statistics === null && statisticsState.status === "loading";
  const statisticsError = statisticsState.error;
  const statisticsStale = statistics !== null && statisticsState.status === "error";
  const alertsError = currentAlertsState.error;
  const alertsPending = !hasCurrentAlerts && currentAlertsState.status === "loading";
  const totalAlertPages = hasCurrentAlerts ? Math.max(1, Math.ceil(alertsMetadata.count / alertsMetadata.limit)) : 1;

  // Statistics settle independently, even if alerts are slow or unavailable.
  useEffect(() => {
    let active = true;
    let pending: Promise<boolean> | null = null;
    const controller = new AbortController();
    if (!canViewStatistics) {
      setStatistics(null);
      setStatisticsState({ status: "error", refreshing: false, error: "Statistics are unavailable for your role. Alerts remain available.", updatedAt: null });
      reloadStatistics.current = async () => false;
      return () => { active = false; controller.abort(); };
    }
    async function requestStatistics(): Promise<boolean> {
      setStatisticsState(previous => ({ ...previous, refreshing: true }));
      try {
        const data = await getStatistics(controller.signal);
        if (!active) return false;
        const result = data as NonNullable<typeof statistics>;
        setStatistics(result);
        setStatisticsState({ status: result.total_alerts === 0 ? "empty" : "success", refreshing: false, error: null, updatedAt: Date.now() });
        return true;
      } catch (error) {
        if (!active) return false;
        setStatisticsState(previous => ({ ...previous, status: "error", refreshing: false, error: error instanceof ApiRequestError && error.status === 403 ? "Statistics are unavailable for your role. Alerts remain available." : getApiErrorMessage(error) }));
        return false;
      }
    }
    function loadStatistics(): Promise<boolean> {
      if (!active) return Promise.resolve(false);
      if (!pending) pending = requestStatistics().finally(() => { pending = null; });
      return pending;
    }
    reloadStatistics.current = loadStatistics;
    void loadStatistics();
    const interval = window.setInterval(() => { void loadStatistics(); }, 5000);
    return () => { active = false; controller.abort(); window.clearInterval(interval); reloadStatistics.current = async () => false; };
  }, [canViewStatistics]);

  useEffect(() => {
    let active = true;
    let pending: Promise<boolean> | null = null;
    const controller = new AbortController();
    setAlertsState(previous => previous.key === alertsQueryKey ? previous : { ...initialSectionState, key: alertsQueryKey });
    async function requestAlerts(): Promise<boolean> {
      setAlertsState(previous => ({ ...previous, refreshing: true }));
      try {
        const data: AlertsResponse = await getAlerts({ severity: backendSeverity, limit: alertsPageSize, offset: requestedOffset }, controller.signal);
        if (!active) return false;
        const limit = Math.max(1, data.limit);
        const lastPage = Math.max(1, Math.ceil(data.count / limit));
        if (requestedOffset > 0 && requestedOffset >= data.count) {
          setAlertsPage(lastPage);
          return false;
        }
        const updatedAt = Date.now();
        setAlerts(data.alerts);
        setAlertsMetadata({ count: data.count, limit, offset: data.offset, key: alertsQueryKey, updatedAt });
        setAlertsState({ status: data.alerts.length === 0 ? "empty" : "success", refreshing: false, error: null, updatedAt, key: alertsQueryKey });
        return true;
      } catch (error) {
        if (!active) return false;
        setAlertsState(previous => ({ ...previous, status: "error", refreshing: false, error: getApiErrorMessage(error), key: alertsQueryKey }));
        return false;
      }
    }
    function loadAlerts(): Promise<boolean> {
      if (!active) return Promise.resolve(false);
      if (!pending) pending = requestAlerts().finally(() => { pending = null; });
      return pending;
    }
    reloadAlerts.current = loadAlerts;
    void loadAlerts();
    const interval = window.setInterval(() => { void loadAlerts(); }, 5000);
    return () => { active = false; controller.abort(); window.clearInterval(interval); reloadAlerts.current = async () => false; };
  }, [backendSeverity, requestedOffset, alertsQueryKey]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        document.querySelector<HTMLInputElement>(".global-search input")?.focus();
      }
      if (event.key === "Escape") { setGlobalSearch(""); setShowNotifications(false); setShowProfile(false); setShowWorkspace(false); setSelectedEvent(null); setRuleModal(null); setConfirmation(null); }
    };
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Element;
      if (!target.closest(".header-profile-wrap")) setShowProfile(false);
      if (!target.closest(".workspace-control")) setShowWorkspace(false);
    };
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("pointerdown", onPointerDown);
    return () => { window.removeEventListener("keydown", onKeyDown); window.removeEventListener("pointerdown", onPointerDown); };
  }, []);

  const liveEvents = useMemo<Event[]>(() => (hasCurrentAlerts ? alerts : []).map(alert => {
    const rawSeverity = String(alert.severity ?? "Informational").toLowerCase();
    const normalizedSeverity: Severity =
      rawSeverity === "high" ? "High" :
      rawSeverity === "medium" ? "Medium" :
      rawSeverity === "low" ? "Low" :
      "Informational";

    const value = (key: string): string => {
      const candidate = alert[key];
      return candidate === undefined || candidate === null ? "" : String(candidate);
    };

    return {
      id: String(alert.id),
      time: value("timestamp") || value("created_at") || "Unknown time",
      severity: normalizedSeverity,
      title: value("title") || value("rule") || "Security alert",
      host: value("host") || value("hostname") || "Unknown host",
      source: value("source") || "AISOP",
      status: value("status") || "Open",
      user: value("user") || value("username") || "",
      ip: value("ip") || value("source_ip") || "",
      process: value("process") || value("process_name") || "",
      raw: value("raw") || value("description") || value("rule") || "",
    };
  }), [alerts, hasCurrentAlerts]);

  const navigate = (next: Page) => { setPage(canAccessPage(next, permissions) ? next : "Overview"); setSearch(""); setSelectedEvent(null); setSelectedHost(null); setSelectedInvestigation(null); setMobileNav(false); setSeverity("All severities"); setHostFilter("All hosts"); setStatusFilter("All statuses"); setTypeFilter("All event types"); setSourceFilter("All sources"); setUserFilter(""); setProcessFilter(""); setAlertsPage(1); };
  const flash = (message: string) => { setNotice(message); window.setTimeout(() => setNotice(""), 4000); };
  const refresh = async () => {
    setRefreshing(true);
    try {
      const [statisticsOK, alertsOK] = await Promise.all([reloadStatistics.current(), reloadAlerts.current()]);
      if (alertsOK && (statisticsOK || !canViewStatistics)) flash("Live security data refreshed.");
    } finally { setRefreshing(false); }
  };
  const filteredEvents = useMemo(() => liveEvents.filter(e => {
    const q = search.trim().toLowerCase(); return (`${e.title} ${e.host} ${e.id} ${e.ip} ${e.raw} ${e.source} ${e.user} ${e.process} ${e.status}`.toLowerCase().includes(q)) && (severity === "All severities" || e.severity === severity) && (hostFilter === "All hosts" || e.host === hostFilter) && (statusFilter === "All statuses" || e.status === statusFilter) && (typeFilter === "All event types" || e.title === typeFilter) && (sourceFilter === "All sources" || e.source === sourceFilter) && e.user.toLowerCase().includes(userFilter.toLowerCase()) && e.process.toLowerCase().includes(processFilter.toLowerCase());
  }), [liveEvents, search, severity, hostFilter, statusFilter, typeFilter, sourceFilter, userFilter, processFilter]);
  const eventColumns = [
    { label: "TIMESTAMP", render: (e: Event) => <span className="mono muted">{e.time}</span> }, { label: "SEVERITY", render: (e: Event) => <Badge type={e.severity}>{e.severity}</Badge> },
    { label: "EVENT TYPE", render: (e: Event) => <span className="strong-cell">{e.title}</span> }, { label: "HOST", render: (e: Event) => <span className="mono">{e.host}</span> }, { label: "SOURCE", render: (e: Event) => <span className="mono muted">{e.source}</span> }, { label: "STATUS", render: (e: Event) => <Badge type={e.status}>{e.status}</Badge> },
  ];
  const hostColumns = [
    { label: "HOSTNAME", render: (h: Host) => <span className="strong-cell mono">{h.name}</span> }, { label: "IP ADDRESS", render: (h: Host) => <span className="mono muted">{h.ip}</span> }, { label: "OPERATING SYSTEM", render: (h: Host) => h.os },
    { label: "ALERTS", render: (h: Host) => <span className="count-cell">{h.alerts}</span> }, { label: "HIGHEST SEVERITY", render: (h: Host) => <Badge type={h.severity}>{h.severity}</Badge> }, { label: "LAST ACTIVITY", render: (h: Host) => <span className="muted">{h.last}</span> }, { label: "STATUS", render: (h: Host) => <Badge type={h.status}>{h.status}</Badge> },
  ];
  const investigationColumns = [
    { label: "INVESTIGATION", render: (i: Investigation) => <span className="investigation-name"><span className="strong-cell">{i.name}</span><small>{i.id}</small></span> }, { label: "SEVERITY", render: (i: Investigation) => <Badge type={i.severity}>{i.severity}</Badge> }, { label: "HOST", render: (i: Investigation) => <span className="mono">{i.host}</span> }, { label: "STATUS", render: (i: Investigation) => <Badge type={investigationStatus[i.id] || i.status}>{investigationStatus[i.id] || i.status}</Badge> }, { label: "ASSIGNED TO", render: (i: Investigation) => <span className="muted">{i.analyst}</span> }, { label: "CREATED", render: (i: Investigation) => <span className="muted">{i.created}</span> }, { label: "LAST UPDATED", render: (i: Investigation) => <span className="muted">{i.updated}</span> },
  ];
  const openRule = (rule: Rule | "new") => { if (!canManageRules) return; setRuleModal(rule); setRuleName(rule === "new" ? "" : rule.name); setRuleDescription(rule === "new" ? "" : rule.description); setRuleSeverity(rule === "new" ? "Medium" : rule.severity); };
  const saveRule = () => { if (!canManageRules || !ruleName.trim() || !ruleDescription.trim()) return; if (ruleModal === "new") { setRules([...rules, { name: ruleName.trim(), description: ruleDescription.trim(), severity: ruleSeverity, enabled: true, source: "auth.log", last: "Never", count: 0 }]); flash("Detection rule created and enabled."); } else if (ruleModal) { setRules(rules.map(r => r.name === ruleModal.name ? { ...r, name: ruleName.trim(), description: ruleDescription.trim(), severity: ruleSeverity } : r)); flash("Detection rule updated."); } setRuleModal(null); };
  const eventFilters = <div className="filters"><SelectField value={severity} onChange={setSeverity} options={["All severities", "High", "Medium", "Low", "Informational"]} label="Filter by severity"/><SelectField value={hostFilter} onChange={setHostFilter} options={["All hosts", ...Array.from(new Set([...hosts.map(h => h.name), ...liveEvents.map(e => e.host)]))]} label="Filter by host"/><SelectField value={typeFilter} onChange={setTypeFilter} options={["All event types", ...Array.from(new Set(liveEvents.map(e => e.title)))]} label="Filter by event type"/><SelectField value={statusFilter} onChange={setStatusFilter} options={["All statuses", "Open", "Investigating", "Resolved"]} label="Filter by status"/></div>;
  const pageDescription: Record<Page,string> = { Overview: "Monitor security activity across your Linux environment.", "Events & Alerts": "Review, filter, and triage detected security activity.", Investigations: "Track active cases and organize your response.", "Linux Hosts": "Monitor the security posture of your Linux infrastructure.", Logs: "Search and inspect raw system and security logs.", "Detection Rules": "Manage the rules that identify suspicious activity.", Reports: "Review security trends and share operational summaries.", Settings: "Manage your workspace preferences." };
  const heading = page === "Overview" ? "Security Overview" : page;
  return <div className="app-shell" data-theme={theme}>
    <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}><div className="brand"><div className="brand-mark"><Icon name="shield" size={22}/></div><div><strong>AISOP</strong><span>LINUX SECURITY</span></div></div><div className="workspace-label">WORKSPACE <Icon name="down" size={13}/></div><div className="workspace-control"><button type="button" className={`workspace-name ${showWorkspace ? "open" : ""}`} aria-haspopup="dialog" aria-expanded={showWorkspace} onClick={() => { setShowWorkspace(!showWorkspace); setShowProfile(false); }}><span className="workspace-avatar">P</span><span>Production Environment</span><Icon name="down" size={14} className="workspace-chevron"/></button>{showWorkspace && <div className="workspace-popover" role="dialog" aria-label="Workspace selector"><span>Current workspace</span><strong>Production Environment</strong><small>Active environment</small></div>}</div><div className="nav-label">MONITORING</div><nav aria-label="Main navigation">{nav.filter(item => canAccessPage(item.label, permissions)).map((item, index) => <div key={item.label}>{index === 4 && <div className="nav-label nav-label-spaced">MANAGEMENT</div>}<button type="button" className={`nav-item ${page === item.label ? "active" : ""}`} onClick={() => navigate(item.label)}><Icon name={item.icon} size={18}/><span>{item.label}</span>{item.label === "Events & Alerts" && <span className="nav-count">{statisticsLoading ? "…" : statistics?.total_alerts ?? (alertsPending ? "…" : alertsMetadata.count)}</span>}</button></div>)}</nav><div className="sidebar-bottom"><div className="system-status"><span className="live-dot status-pulse"/><div><strong>{currentUser.username}</strong><span>{currentUser.role.toUpperCase()}</span></div></div></div></aside>
    {mobileNav && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNav(false)}/>}
    <div className="main-area"><header className="topbar"><div className="topbar-left"><button type="button" className="mobile-menu" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Icon name="grid"/></button><span className="breadcrumb">Workspace</span><Icon name="chevron" size={13}/><span className="breadcrumb-current">{page}</span></div><div className="topbar-right"><SearchField value={globalSearch} onChange={setGlobalSearch} placeholder="Search events, hosts..." className="global-search"/><span className="keyboard-hint">⌘ K</span><span className="topbar-divider"/><button type="button" className="icon-button" aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"} title={theme === "dark" ? "Light mode" : "Dark mode"} onClick={toggleTheme}><Icon name={theme === "dark" ? "sun" : "moon"} size={19}/></button><div className="notification-wrap"><button type="button" className="icon-button" aria-label="Notifications" onClick={() => setShowNotifications(!showNotifications)}><Icon name="bell" size={19}/>{(statistics?.severity.high ?? 0) > 0 && <span className="notification-dot"/>}</button>{showNotifications && <div className="notification-popover"><strong>Notifications</strong><p>{statistics ? <>{statistics.severity.high} high-priority {statistics.severity.high === 1 ? "alert needs" : "alerts need"} review.</> : "Alert statistics are unavailable. Open alerts to review security activity."}</p><Button variant="ghost" className="view-link" onClick={() => { navigate("Events & Alerts"); setSeverity("High"); setShowNotifications(false); }}>View high alerts <Icon name="arrow" size={14}/></Button></div>}</div><span className="topbar-divider"/><div className="header-profile-wrap"><button type="button" className={`header-profile ${showProfile ? "open" : ""}`} aria-haspopup="menu" aria-expanded={showProfile} onClick={() => { setShowProfile(!showProfile); setShowWorkspace(false); }}><span className="top-avatar">{initials}</span><span className="header-profile-copy"><strong>{currentUser.username}</strong><small>{currentUser.role.toUpperCase()}</small></span><Icon name="down" size={14} className="profile-chevron"/></button>{showProfile && <div className="profile-menu" role="menu">{canAccessSettings && <><button type="button" role="menuitem" onClick={() => { setShowProfile(false); navigate("Settings"); }}><Icon name="user" size={16}/>Profile</button><button type="button" role="menuitem" onClick={() => { setShowProfile(false); navigate("Settings"); }}><Icon name="settings" size={16}/>Settings</button><span className="profile-menu-divider"/></>}<button type="button" role="menuitem" className="logout-item" onClick={() => onLogout()}><Icon name="logout" size={16}/>Logout</button></div>}</div></div></header>
    {globalSearch.trim() && <div className="global-results"><div className="global-results-title">Search results for “{globalSearch}”</div>{liveEvents.filter(e => `${e.title} ${e.host} ${e.id}`.toLowerCase().includes(globalSearch.toLowerCase())).slice(0,4).map(e => <button key={e.id} onClick={() => { setGlobalSearch(""); navigate("Events & Alerts"); setSelectedEvent(e); }}><Icon name="activity" size={15}/><span>{e.title}<small>{e.id} · {e.host}</small></span><Icon name="chevron" size={14}/></button>)}{!liveEvents.some(e => `${e.title} ${e.host} ${e.id}`.toLowerCase().includes(globalSearch.toLowerCase())) && <p>No matching events. Try a host name or event type.</p>}</div>}
    <main className="content"><div className="page-intro"><div><div className="eyebrow">SECURITY OPERATIONS <span>/</span> {page.toUpperCase()}</div><h1>{selectedHost ? selectedHost.name : selectedInvestigation ? selectedInvestigation.name : heading}</h1><p>{selectedHost ? `${selectedHost.os} · ${selectedHost.ip}` : selectedInvestigation ? `${selectedInvestigation.id} · ${selectedInvestigation.host}` : pageDescription[page]}</p></div><div className="intro-actions">{(selectedHost || selectedInvestigation) && <Button icon="chevron" onClick={() => { setSelectedHost(null); setSelectedInvestigation(null); }}>Back to {page}</Button>}<SelectField value={timeRange} onChange={setTimeRange} options={["Last 24 hours", "Last 7 days", "Last 30 days"]} label="Time range"/><Button icon="refresh" title="Refresh live security data" onClick={refresh} disabled={refreshing}>{refreshing ? "Refreshing..." : "Refresh"}</Button></div></div>
    {refreshing && <div className="loading-state" role="status"><span className="loading-spinner"/>Refreshing live security data...</div>}
    <DataSectionStatus label="Statistics" state={statisticsState} hasData={statistics !== null} onRetry={() => { void reloadStatistics.current(); }} retryAllowed={canViewStatistics}/>
    <DataSectionStatus label="Alerts" state={{ ...currentAlertsState, updatedAt: hasCurrentAlerts ? alertsMetadata.updatedAt : null }} hasData={hasCurrentAlerts} onRetry={() => { void reloadAlerts.current(); }}/>
    {page === "Overview" && <>
      <div className="overview-status"><span className="live-dot"/><strong>Monitoring active</strong><span className="status-separator"/> 24 sample hosts <span className="status-separator"/> Demo data</div>
      <div className="stats-grid">
        <StatCard
          label="Total Alerts"
          value={statisticsLoading ? "..." : String(statistics?.total_alerts ?? "—")}
          change={statisticsStale ? "Stale data" : statisticsState.refreshing ? "Updating…" : "Live data"}
          tone="info"
          icon="activity"
          onClick={() => navigate("Events & Alerts")}
        />
        <StatCard
          label="High Alerts"
          value={statisticsLoading ? "..." : String(statistics?.severity.high ?? "—")}
          change="Live data"
          tone="danger"
          icon="shield"
          onClick={() => { navigate("Events & Alerts"); setSeverity("High"); }}
        />
        <StatCard
          label="Medium Alerts"
          value={statisticsLoading ? "..." : String(statistics?.severity.medium ?? "—")}
          change="Live data"
          tone="warning"
          icon="activity"
          onClick={() => { navigate("Events & Alerts"); setSeverity("Medium"); }}
        />
        <StatCard
          label="Low Alerts"
          value={statisticsLoading ? "..." : String(statistics?.severity.low ?? "—")}
          change="Live data"
          tone="success"
          icon="shield"
          onClick={() => { navigate("Events & Alerts"); setSeverity("Low"); }}
        />
      </div>
      <div className="overview-charts"><Panel className="activity-panel"><SectionHeading title="Security Activity" subtitle="Event volume across your environment"/><ActivityChart/></Panel><Panel className="severity-panel"><SectionHeading title="Alert Severity" subtitle="Distribution · current alert statistics"/>{statistics ? <SeverityChart statistics={statistics}/> : <p className="drawer-help">{statisticsLoading ? "Loading statistics…" : statisticsError || "Statistics unavailable."}</p>}</Panel></div>
      <Panel><SectionHeading title="Top Affected Hosts" subtitle="Hosts with the most security alerts" action={<Button variant="ghost" className="view-link" onClick={() => navigate("Linux Hosts")}>View all hosts <Icon name="arrow" size={15}/></Button>}/><DataTable columns={hostColumns} rows={hosts.slice(0,4)} rowKey={h => h.name} onRow={h => { navigate("Linux Hosts"); setSelectedHost(h); }}/></Panel>
      <Panel><SectionHeading title="Recent Security Events" subtitle="Latest events requiring analyst attention" action={<Button variant="ghost" className="view-link" onClick={() => navigate("Events & Alerts")}>View all events <Icon name="arrow" size={15}/></Button>}/><DataTable columns={eventColumns} rows={liveEvents.slice(0,6)} empty={alertsPending || (alertsError && !hasCurrentAlerts) ? <></> : <EmptyState title="No alerts found" description="No alerts have been returned by the API."/>} rowKey={e => e.id} onRow={e => { navigate("Events & Alerts"); setSelectedEvent(e); }}/></Panel>
      <Panel><SectionHeading title="Open Investigations" subtitle="Cases currently in progress" action={<Button variant="ghost" className="view-link" onClick={() => navigate("Investigations")}>View investigations <Icon name="arrow" size={15}/></Button>}/><DataTable columns={investigationColumns.filter(c => c.label !== "ASSIGNED TO")} rows={investigations.filter(i => i.status !== "Resolved").slice(0,4)} rowKey={i => i.id} onRow={i => { navigate("Investigations"); setSelectedInvestigation(i); }}/></Panel>
    </>}
    {page === "Events & Alerts" && <Panel className="page-panel">
      <SectionHeading title="Security Events" subtitle="Select an event to inspect its details and raw log" action={<span className="result-count">{alertsPending ? "Loading…" : !hasCurrentAlerts ? "Unavailable" : `${filteredEvents.length} shown · ${alertsMetadata.count} total`}</span>}/>
      <div className="toolbar"><SearchField value={search} onChange={setSearch} placeholder="Search events, hosts, IPs..."/>{eventFilters}</div>
      <p className="muted" style={{ padding: "0 20px" }}>Search and host, event type, and status filters apply to the current page.</p>
      <DataTable columns={eventColumns} rows={alertsPending ? [] : filteredEvents} rowKey={e => e.id} onRow={setSelectedEvent} empty={alertsPending || (alertsError && !hasCurrentAlerts) ? <></> : <EmptyState title={alertsMetadata.count === 0 ? backendSeverity ? `No ${backendSeverity} alerts found` : "No alerts found" : "No matching alerts on this page"} description={alertsMetadata.count === 0 ? "Try another severity or refresh for new alerts." : "Try adjusting your filters or checking another page."} onReset={() => { setSearch(""); setSeverity("All severities"); setHostFilter("All hosts"); setStatusFilter("All statuses"); setTypeFilter("All event types"); setSourceFilter("All sources"); setUserFilter(""); setProcessFilter(""); }}/>} />
      <div className="table-footer" style={{ flexWrap: "wrap", gap: 12 }}>
        <span aria-live="polite">{alertsPending ? "Loading page…" : !hasCurrentAlerts ? "Alert data unavailable for this page." : `Showing ${filteredEvents.length} of ${liveEvents.length} loaded alerts · Records ${liveEvents.length ? alertsMetadata.offset + 1 : 0}–${alertsMetadata.offset + liveEvents.length} of ${alertsMetadata.count}`}</span>
        <div role="group" aria-label="Alerts pagination" style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <Button onClick={() => setAlertsPage(current => Math.max(1, current - 1))} disabled={alertsPending || currentAlertsState.refreshing || alertsPage <= 1}>Previous</Button>
          <span>Page {alertsPage} of {hasCurrentAlerts ? totalAlertPages : "…"}</span>
          <Button onClick={() => setAlertsPage(current => Math.min(totalAlertPages, current + 1))} disabled={alertsPending || !hasCurrentAlerts || currentAlertsState.refreshing || alertsMetadata.offset + alertsMetadata.limit >= alertsMetadata.count}>Next</Button>
        </div>
      </div>
    </Panel>}
    {page === "Investigations" && (selectedInvestigation ? <><div className="detail-layout"><div className="detail-main"><Panel><SectionHeading title="Summary" action={<Badge type={selectedInvestigation.severity}>{selectedInvestigation.severity}</Badge>}/><p className="body-copy">{selectedInvestigation.summary}</p><div className="info-grid"><Info label="Affected host" value={selectedInvestigation.host}/><Info label="Assigned analyst" value={selectedInvestigation.analyst}/><Info label="Created" value={selectedInvestigation.created}/><Info label="Last updated" value={selectedInvestigation.updated}/></div></Panel><Panel><SectionHeading title="Event Timeline" subtitle="Activity related to this investigation"/><div className="timeline">{liveEvents.filter(e => e.host === selectedInvestigation.host).slice(0,4).map(e => <button key={e.id} className="timeline-item" onClick={() => setSelectedEvent(e)}><span className="timeline-node"/><span><small>{e.time}</small><strong>{e.title}</strong><span>{e.source} · {e.id}</span></span><Icon name="chevron" size={15}/></button>)}</div></Panel><Panel><SectionHeading title="Evidence & Analyst Notes"/><div className="evidence-block"><Icon name="terminal" size={18}/><div><strong>Evidence from related events</strong><p>Review raw event records in the timeline to validate activity on {selectedInvestigation.host}.</p></div></div><label className="field-label" htmlFor="analyst-notes">Analyst notes</label><textarea id="analyst-notes" readOnly={!canEditInvestigations} className="notes-input" placeholder="Add your findings and next steps..." rows={4}/><div className="field-action"><Button disabled={!canEditInvestigations} onClick={() => { if (canEditInvestigations) flash("Analyst note saved for this session."); }}>Save note</Button></div></Panel></div><div className="detail-side"><Panel><SectionHeading title="Case Status"/><Badge type={investigationStatus[selectedInvestigation.id] || selectedInvestigation.status}>{investigationStatus[selectedInvestigation.id] || selectedInvestigation.status}</Badge>{canEditInvestigations && <><label className="field-label top-gap">Update status</label><SelectField value={investigationStatus[selectedInvestigation.id] || selectedInvestigation.status} onChange={value => { if (canEditInvestigations) setInvestigationStatus({ ...investigationStatus, [selectedInvestigation.id]: value }); }} options={["Open", "Investigating", "Resolved"]} label="Investigation status"/></>}</Panel><Panel><SectionHeading title="Affected Host"/><button className="linked-host" onClick={() => { const h = hosts.find(h => h.name === selectedInvestigation.host); if (h) { navigate("Linux Hosts"); setSelectedHost(h); } }}><Icon name="server" size={18}/><span>{selectedInvestigation.host}</span><Icon name="arrow" size={15}/></button></Panel></div></div></> : <Panel className="page-panel"><SectionHeading title="Investigation Queue" subtitle="Coordinate and track security cases" action={<span className="result-count">{investigations.filter(i => (investigationStatus[i.id] || i.status) !== "Resolved").length} active cases</span>}/><div className="toolbar"><SearchField value={search} onChange={setSearch} placeholder="Search investigations..."/><SelectField value={statusFilter} onChange={setStatusFilter} options={["All statuses", "Open", "Investigating", "Resolved"]} label="Filter by status"/><SelectField value={severity} onChange={setSeverity} options={["All severities", "High", "Medium", "Low"]} label="Filter by severity"/></div><DataTable columns={investigationColumns} rows={investigations.filter(i => `${i.name} ${i.host} ${i.id}`.toLowerCase().includes(search.toLowerCase()) && (statusFilter === "All statuses" || (investigationStatus[i.id] || i.status) === statusFilter) && (severity === "All severities" || i.severity === severity))} rowKey={i => i.id} onRow={setSelectedInvestigation} empty={<EmptyState onReset={() => { setSearch(""); setStatusFilter("All statuses"); setSeverity("All severities"); }}/>} /></Panel>)}
    {page === "Linux Hosts" && (selectedHost ? <><div className="host-summary-grid"><Panel><span className="mini-label">HOST STATUS</span><div className="host-summary-value"><Badge type={selectedHost.status}>{selectedHost.status}</Badge></div><small>Last seen {selectedHost.last}</small></Panel><Panel><span className="mini-label">SECURITY ALERTS</span><div className="host-summary-value">{selectedHost.alerts}</div><small>Highest: {selectedHost.severity}</small></Panel><Panel><span className="mini-label">CPU USAGE</span><div className="host-summary-value">{selectedHost.cpu}%</div><div className="meter"><span style={{ width: `${selectedHost.cpu}%` }}/></div></Panel><Panel><span className="mini-label">MEMORY USAGE</span><div className="host-summary-value">{selectedHost.memory}%</div><div className="meter"><span style={{ width: `${selectedHost.memory}%` }}/></div></Panel></div><div className="tabs" role="tablist" aria-label="Host details">{["Overview", "Recent Events", "Authentication", "Processes", "Network Activity", "Security Alerts", "System Information"].map(t => <button role="tab" aria-selected={hostTab === t} key={t} className={hostTab === t ? "active" : ""} onClick={() => setHostTab(t)}>{t}</button>)}</div><Panel className="page-panel">{["Overview", "System Information"].includes(hostTab) ? <><SectionHeading title={hostTab === "Overview" ? "Host Overview" : "System Information"}/><div className="info-grid host-info"><Info label="Hostname" value={selectedHost.name}/><Info label="IP address" value={selectedHost.ip}/><Info label="Operating system" value={selectedHost.os}/><Info label="Last seen" value={selectedHost.last}/><Info label="Risk level" value={<Badge type={selectedHost.severity}>{selectedHost.severity}</Badge>}/><Info label="Monitoring status" value={<Badge type={selectedHost.status}>{selectedHost.status}</Badge>}/></div></> : hostTab === "Network Activity" ? <EmptyState title="No network activity to display" description="No network activity records are available for this host in the selected time range."/> : <><SectionHeading title={hostTab} subtitle={`Recorded activity on ${selectedHost.name}`}/><DataTable columns={eventColumns} rows={liveEvents.filter(e => e.host === selectedHost.name && (hostTab !== "Authentication" || e.source === "auth.log") && (hostTab !== "Processes" || e.source === "auditd") && (hostTab !== "Security Alerts" || ["High"].includes(e.severity)))} rowKey={e => e.id} onRow={setSelectedEvent} empty={<EmptyState title="No matching activity" description="No records match this category and time range."/>}/></>}</Panel></> : <Panel className="page-panel"><SectionHeading title="Monitored Hosts" subtitle="Connected Linux assets and their security posture" action={<span className="result-count">24 hosts monitored</span>}/><div className="toolbar"><SearchField value={search} onChange={setSearch} placeholder="Search host or IP address..."/><SelectField value={severity} onChange={setSeverity} options={["All severities", "High", "Medium", "Low"]} label="Filter by risk"/></div><DataTable columns={[...hostColumns, { label: "CPU / MEMORY", render: (h: Host) => <span className="mono muted">{h.cpu}% / {h.memory}%</span> }]} rows={hosts.filter(h => `${h.name} ${h.ip} ${h.os}`.toLowerCase().includes(search.toLowerCase()) && (severity === "All severities" || h.severity === severity))} rowKey={h => h.name} onRow={h => { setSelectedHost(h); setHostTab("Overview"); }} empty={<EmptyState onReset={() => { setSearch(""); setSeverity("All severities"); }}/>} /></Panel>)}
    {page === "Logs" && <Panel className="page-panel"><SectionHeading title="Log Explorer" subtitle="Search system, authentication, and audit logs" action={<span className="result-count">{filteredEvents.length} log entries</span>}/><div className="toolbar"><SearchField value={search} onChange={setSearch} placeholder="Search raw logs, hosts, IPs..."/><div className="filters"><SelectField value={hostFilter} onChange={setHostFilter} options={["All hosts", ...hosts.map(h => h.name)]} label="Filter by host"/><SelectField value={sourceFilter} onChange={setSourceFilter} options={["All sources", "auth.log", "auditd", "syslog"]} label="Filter by log source"/><SelectField value={severity} onChange={setSeverity} options={["All severities", "High", "Medium", "Low", "Informational"]} label="Filter by severity"/></div></div><div className="toolbar secondary-toolbar"><SearchField value={userFilter} onChange={setUserFilter} placeholder="Filter by user"/><SearchField value={processFilter} onChange={setProcessFilter} placeholder="Filter by process"/></div><div className="table-scroll"><table><thead><tr><th>TIMESTAMP</th><th>SEVERITY</th><th>HOST</th><th>SOURCE</th><th>PROCESS</th><th>MESSAGE</th><th></th></tr></thead><tbody>{filteredEvents.map(e => <Fragment key={e.id}><tr className="interactive-row" tabIndex={0} onClick={() => setExpandedLog(expandedLog === e.id ? null : e.id)} onKeyDown={key => { if (key.key === "Enter" || key.key === " ") { key.preventDefault(); setExpandedLog(expandedLog === e.id ? null : e.id); } }}><td className="mono muted">{e.time}</td><td><Badge type={e.severity}>{e.severity}</Badge></td><td className="mono">{e.host}</td><td className="mono muted">{e.source}</td><td className="mono muted">{e.process}</td><td className="log-message">{e.title}</td><td><Icon name="down" size={15} className={expandedLog === e.id ? "rotate-icon" : ""}/></td></tr>{expandedLog === e.id && <tr className="raw-row"><td colSpan={7}><div><span>RAW LOG · {e.id}</span><code>{e.raw}</code></div></td></tr>}</Fragment>)}</tbody></table>{filteredEvents.length === 0 && !alertsPending && !(alertsError && !hasCurrentAlerts) && <EmptyState title={alertsMetadata.count === 0 ? "No alerts found" : "No matching alerts on this page"} onReset={() => { setSearch(""); setHostFilter("All hosts"); setSourceFilter("All sources"); setSeverity("All severities"); setUserFilter(""); setProcessFilter(""); }}/>}</div></Panel>}
    {page === "Detection Rules" && <Panel className="page-panel"><SectionHeading title="Detection Rules" subtitle="Configure the signals that generate security alerts" action={canManageRules ? <Button variant="primary" icon="plus" onClick={() => openRule("new")}>Create Rule</Button> : undefined}/><div className="toolbar"><SearchField value={search} onChange={setSearch} placeholder="Search detection rules..."/><SelectField value={statusFilter} onChange={setStatusFilter} options={["All statuses", "Enabled", "Disabled"]} label="Filter by status"/></div><DataTable columns={[{ label: "RULE NAME", render: (r: Rule) => <span className="investigation-name"><span className="strong-cell">{r.name}</span><small>{r.description}</small></span> }, { label: "SEVERITY", render: (r: Rule) => <Badge type={r.severity}>{r.severity}</Badge> }, { label: "STATUS", render: (r: Rule) => <Badge type={r.enabled ? "Enabled" : "Disabled"}>{r.enabled ? "Enabled" : "Disabled"}</Badge> }, { label: "EVENT SOURCE", render: (r: Rule) => <span className="mono">{r.source}</span> }, { label: "LAST TRIGGERED", render: (r: Rule) => <span className="muted">{r.last}</span> }, { label: "TRIGGERS", render: (r: Rule) => r.count }, { label: "ACTIONS", render: (r: Rule) => <div className="row-actions"><Button disabled={!canManageRules} variant="ghost" onClick={() => openRule(r)}>Edit</Button><Button variant="ghost" disabled={!canManageRules} onClick={() => { if (!canManageRules) return; r.enabled ? setConfirmation(rules.indexOf(r)) : (setRules(rules.map(x => x === r ? { ...x, enabled: true } : x)), flash(`${r.name} enabled.`)); }}>{r.enabled ? "Disable" : "Enable"}</Button></div> }]} rows={rules.filter(r => `${r.name} ${r.description}`.toLowerCase().includes(search.toLowerCase()) && (statusFilter === "All statuses" || (r.enabled ? "Enabled" : "Disabled") === statusFilter))} rowKey={r => r.name} empty={<EmptyState onReset={() => { setSearch(""); setStatusFilter("All statuses"); }}/>} /></Panel>}
    {page === "Reports" && <><div className="report-header"><div><span className="mini-label">SECURITY REPORT</span><h2>Environment summary</h2><p>Operational overview for {timeRange.toLowerCase()}</p></div><Button variant="primary" icon="download" onClick={() => { const activeInvestigations = investigations.filter(i => (investigationStatus[i.id] || i.status) !== "Resolved").length; const csv = `Metric,Value\nTotal alerts,${statistics?.total_alerts ?? "—"}\nHigh alerts,${statistics?.severity.high ?? "—"}\nMedium alerts,${statistics?.severity.medium ?? "—"}\nLow alerts,${statistics?.severity.low ?? "—"}\nActive investigations,${activeInvestigations}\n`; const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" })); a.download = "aisop-security-report.csv"; a.click(); URL.revokeObjectURL(a.href); flash("Report exported as CSV."); }}>Export report</Button></div><div className="report-grid"><Panel><SectionHeading title="Security Summary"/><div className="report-metrics"><div><strong>{statistics?.total_alerts ?? "—"}</strong><span>Alerts recorded</span></div><div><strong>{statistics?.severity.high ?? "—"}</strong><span>High-priority alerts</span></div><div><strong>{investigations.filter(i => (investigationStatus[i.id] || i.status) !== "Resolved").length}</strong><span>Active investigations</span></div></div></Panel><Panel><SectionHeading title="Investigation Statistics"/><div className="severity-rows report-rows"><div><span>Open</span><strong>2</strong></div><div><span>Investigating</span><strong>2</strong></div><div><span>Resolved</span><strong>1</strong></div></div></Panel><Panel className="report-wide"><SectionHeading title="Alert Trends" subtitle="Security event volume by severity"/><ActivityChart/></Panel><Panel><SectionHeading title="Top Affected Hosts"/><div className="rank-list">{hosts.slice(0,4).map((h, i) => <button key={h.name} onClick={() => { navigate("Linux Hosts"); setSelectedHost(h); }}><span className="rank">0{i+1}</span><span className="mono">{h.name}</span><strong>{h.alerts} alerts</strong></button>)}</div></Panel><Panel><SectionHeading title="Event Statistics"/>{statistics ? <SeverityChart statistics={statistics}/> : <p className="drawer-help">{statisticsLoading ? "Loading statistics…" : statisticsError || "Statistics unavailable."}</p>}</Panel></div></>}
    {page === "Settings" && canAccessSettings && <div className="settings-layout"><Panel><SectionHeading title="Workspace" subtitle="Your current monitoring environment"/><div className="info-grid"><Info label="Workspace name" value="Production Environment"/><Info label="Environment" value="Linux Infrastructure"/><Info label="Monitored hosts" value="24 connected"/><Info label="Data status" value="Syncing normally"/></div></Panel><Panel><SectionHeading title="Profile"/><div className="info-grid"><Info label="Name" value={currentUser.username}/><Info label="Role" value={currentUser.role.toUpperCase()}/></div></Panel></div>}
    </main></div>
    {selectedEvent && <><button type="button" className="drawer-backdrop" onClick={() => setSelectedEvent(null)} aria-label="Close event details"></button><aside className="detail-drawer" aria-label="Event details"><div className="drawer-header"><div><span className="mini-label">EVENT DETAILS · {selectedEvent.id}</span><h2>{selectedEvent.title}</h2></div><button className="icon-button" onClick={() => setSelectedEvent(null)} aria-label="Close details"><Icon name="close"/></button></div><div className="drawer-content"><div className="drawer-badges"><Badge type={selectedEvent.severity}>{selectedEvent.severity}</Badge><Badge type={selectedEvent.status}>{selectedEvent.status}</Badge></div><p className="drawer-help">Detected on {selectedEvent.host} from {selectedEvent.source}.</p><div className="drawer-section"><h3>Event information</h3><div className="drawer-info"><Info label="Timestamp" value={selectedEvent.time}/><Info label="Host" value={selectedEvent.host}/><Info label="User" value={selectedEvent.user}/><Info label="Source IP" value={selectedEvent.ip}/><Info label="Process" value={selectedEvent.process}/><Info label="Log source" value={selectedEvent.source}/></div></div><div className="drawer-section"><h3>Raw event / log</h3><pre className="raw-log">{selectedEvent.raw}</pre></div><div className="drawer-section"><h3>Related events</h3>{liveEvents.filter(e => e.host === selectedEvent.host && e.id !== selectedEvent.id).slice(0,3).map(e => <button className="related-event" key={e.id} onClick={() => setSelectedEvent(e)}><span>{e.title}<small>{e.time} · {e.id}</small></span><Icon name="chevron" size={15}/></button>)}{liveEvents.filter(e => e.host === selectedEvent.host && e.id !== selectedEvent.id).length === 0 && <p className="muted">No related events on this host.</p>}</div><div className="drawer-section"><h3>Investigation</h3>{investigations.find(i => i.host === selectedEvent.host) ? <button className="related-event" onClick={() => { const i = investigations.find(i => i.host === selectedEvent.host)!; setSelectedEvent(null); navigate("Investigations"); setSelectedInvestigation(i); }}><span>{investigations.find(i => i.host === selectedEvent.host)!.name}<small>Open investigation</small></span><Icon name="arrow" size={15}/></button> : <p className="muted">No investigation linked to this event.</p>}</div></div></aside></>}
    {canManageRules && ruleModal && <div className="modal-layer" role="presentation" onMouseDown={e => { if (e.target === e.currentTarget) setRuleModal(null); }}><div className="modal" role="dialog" aria-modal="true" aria-label={ruleModal === "new" ? "Create detection rule" : "Edit detection rule"}><div className="modal-top"><div><span className="mini-label">DETECTION RULES</span><h2>{ruleModal === "new" ? "Create detection rule" : "Edit detection rule"}</h2></div><button className="icon-button" onClick={() => setRuleModal(null)} aria-label="Close dialog"><Icon name="close"/></button></div><p className="muted">Define a rule to flag suspicious activity in your Linux logs.</p><label className="field-label" htmlFor="rule-name">Rule name</label><input id="rule-name" className="text-input" value={ruleName} onChange={e => setRuleName(e.target.value)} placeholder="e.g. Unusual SSH access"/><label className="field-label" htmlFor="rule-description">Description</label><textarea id="rule-description" className="notes-input" value={ruleDescription} onChange={e => setRuleDescription(e.target.value)} placeholder="Describe what this rule detects" rows={3}/><label className="field-label">Severity</label><SelectField value={ruleSeverity} onChange={v => setRuleSeverity(v as Severity)} options={["High", "Medium", "Low", "Informational"]} label="Rule severity"/><div className="modal-actions"><Button onClick={() => setRuleModal(null)}>Cancel</Button><Button variant="primary" onClick={saveRule} disabled={!ruleName.trim() || !ruleDescription.trim()}>{ruleModal === "new" ? "Create rule" : "Save changes"}</Button></div></div></div>}
    {canManageRules && confirmation !== null && <div className="modal-layer"><div className="modal confirm-modal" role="alertdialog" aria-modal="true" aria-label="Disable detection rule"><div className="modal-top"><h2>Disable detection rule?</h2></div><p>“{rules[confirmation]?.name}” will stop generating new alerts. You can re-enable it at any time.</p><div className="modal-actions"><Button onClick={() => setConfirmation(null)}>Cancel</Button><Button variant="primary" onClick={() => { if (!canManageRules) return; const rule = rules[confirmation]; if (!rule) { setConfirmation(null); return; } const name = rule.name; setRules(rules.map((r, i) => i === confirmation ? { ...r, enabled: false } : r)); setConfirmation(null); flash(`${name} disabled.`); }}>Disable rule</Button></div></div></div>}
    {notice && <div className="toast" role="status"><Icon name="check" size={17}/>{notice}<button aria-label="Dismiss notification" onClick={() => setNotice("")}><Icon name="close" size={14}/></button></div>}
  </div>;
}
function Info({ label, value }: { label: string; value: ReactNode }) { return <div className="info-item"><span>{label}</span><strong>{value}</strong></div>; }


export default function App() {
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [checking, setChecking] = useState(true);
  const [connectionError, setConnectionError] = useState<"unavailable" | "verification" | null>(null);
  const [connectionAttempt, setConnectionAttempt] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [authError, setAuthError] = useState("");
  const [theme, setTheme] = useState<"dark" | "light">(() => localStorage.getItem("aisop-theme") === "light" ? "light" : "dark");
  const loginPending = useRef(false);
  const toggleTheme = () => setTheme(previous => {
    const next = previous === "dark" ? "light" : "dark";
    localStorage.setItem("aisop-theme", next);
    return next;
  });
  const resetSession = useCallback((message = "") => {
    setCurrentUser(null);
    setConnectionError(null);
    setPassword("");
    setAuthError(message);
    setChecking(false);
  }, []);
  const endSession = useCallback((message = "") => {
    logout();
    resetSession(message);
  }, [resetSession]);

  useEffect(() => subscribeUnauthorized(error => resetSession(getApiErrorMessage(error))), [resetSession]);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setChecking(true);
    setAuthError("");
    async function restoreSession() {
      try {
        if (hasAccessToken()) {
          const user = await getCurrentUser(controller.signal);
          if (active) { setCurrentUser(user); setConnectionError(null); }
        } else if (active) {
          setConnectionError(null);
        }
      } catch (error) {
        if (active) {
          const message = getApiErrorMessage(error);
          if (!(error instanceof ApiRequestError && error.status === 401)) {
            setConnectionError(isBackendUnavailable(error) ? "unavailable" : "verification");
            setAuthError(message);
          }
        }
      } finally {
        if (active) setChecking(false);
      }
    }
    void restoreSession();
    return () => { active = false; controller.abort(); };
  }, [connectionAttempt]);

  const retryConnection = () => {
    if (checking) return;
    setChecking(true);
    setConnectionAttempt(attempt => attempt + 1);
  };

  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if ((event.key === "aisop_access_token" || event.key === null) && currentUser) {
        resetSession("Your session changed in another tab. Please sign in again.");
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [currentUser, resetSession]);

  async function signIn(event: import("react").FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (loginPending.current || !username.trim() || !password) return;
    loginPending.current = true;
    setSubmitting(true);
    setAuthError("");
    try {
      await login(username.trim(), password);
      const user = await getCurrentUser();
      setPassword("");
      setCurrentUser(user);
    } catch (error) {
      const message = getApiErrorMessage(error);
      if (!(error instanceof ApiRequestError && error.status === 401)) {
        if (isBackendUnavailable(error) && hasAccessToken()) {
          setPassword("");
          setConnectionError("unavailable");
        }
        setAuthError(message);
      }
    } finally {
      loginPending.current = false;
      setSubmitting(false);
    }
  }

  // Protected components and their effects exist only after /auth/me succeeds.
  if (!checking && currentUser) return <Dashboard currentUser={currentUser} theme={theme} toggleTheme={toggleTheme} onLogout={endSession}/>;

  return <div className="app-shell login-shell" data-theme={theme}>
    <div className="login-grid-pattern" aria-hidden="true"/>
    <header className="login-header"><div className="login-brand"><span className="login-brand-mark"><Icon name="shield" size={21}/></span><span><strong>AISOP</strong><small>LINUX SECURITY</small></span></div><button type="button" className="login-theme-toggle" onClick={toggleTheme} aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}><Icon name={theme === "dark" ? "sun" : "moon"} size={18}/></button></header>
    <main className="login-main">
      <section className="login-context" aria-label="Platform overview">
        <h1>Protect every Linux workload from one command center.</h1>
        <div className="login-capabilities">
          <div><span><Icon name="activity" size={17}/></span><strong>Real-time monitoring</strong><small>Continuous visibility across connected hosts</small></div>
        </div>
      </section>
      <section className="login-panel" aria-labelledby="login-title">
        <div className="login-panel-top"><span className="login-security-icon"><Icon name="lock" size={19}/></span><span>AUTHORIZED ACCESS</span></div>
        <div className="login-heading"><span>{connectionError ? "CONNECTION STATUS" : "WELCOME BACK"}</span><h2 id="login-title">{connectionError === "unavailable" ? "AISOP server unavailable" : connectionError ? "Unable to verify session" : "Sign in to AISOP"}</h2><p>{connectionError ? "Retry to reconnect to your workspace." : "Enter your workspace credentials to continue."}</p></div>
        {connectionError ? <div className="login-form" aria-busy={checking}>
          <p className="login-message visible" role="alert">{connectionError === "unavailable" ? "Unable to connect to AISOP server." : authError || "Unable to verify your session. Please try again."}</p>
          <button type="button" className="login-submit" onClick={retryConnection} disabled={checking}>{checking ? <><span className="loading-spinner"/><span role="status">Connecting…</span></> : <><span>Retry Connection</span><Icon name="refresh" size={17}/></>}</button>
        </div> : checking ? <div className="login-message" role="status"><span className="loading-spinner"/> Checking authentication…</div> : <form className="login-form" onSubmit={signIn} aria-busy={submitting}>
          <label><span>Username</span><div className="login-input"><Icon name="user" size={17}/><input name="username" required disabled={submitting} aria-describedby={authError ? "login-error" : undefined} value={username} onChange={event => { setUsername(event.target.value); setAuthError(""); }} autoComplete="username" placeholder="Enter your username" autoFocus/></div></label>
          <label><span>Password</span><div className="login-input"><Icon name="lock" size={17}/><input name="password" required disabled={submitting} aria-describedby={authError ? "login-error" : undefined} type={showPassword ? "text" : "password"} value={password} onChange={event => { setPassword(event.target.value); setAuthError(""); }} autoComplete="current-password" placeholder="Enter your password"/><button type="button" className="password-toggle" disabled={submitting} onClick={() => setShowPassword(current => !current)} aria-label={showPassword ? "Hide password" : "Show password"} aria-pressed={showPassword}><Icon name={showPassword ? "eye-off" : "eye"} size={18}/></button></div></label>
          <p id="login-error" className={`login-message ${authError ? "visible" : ""}`} role={authError ? "alert" : "status"}>{authError || "Secure workspace authentication"}</p>
          <button type="submit" className="login-submit" disabled={submitting || !username.trim() || !password}>{submitting ? <><span className="loading-spinner"/><span>Signing in…</span></> : <><span>Sign in securely</span><Icon name="arrow" size={17}/></>}</button>
        </form>}
        <div className="login-trust"><Icon name="shield" size={15}/><span>Encrypted connection</span><i/><span>Authorized users only</span></div>
      </section>
    </main>
  </div>;
}
