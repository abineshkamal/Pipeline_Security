"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createContext, useContext, useEffect, useState } from "react";
import { api, getOrg, getToken, setOrg, setToken, type Me } from "@/lib/api";
import { Loading } from "./ui";

const MeCtx = createContext<{ me: Me | null; role: string }>({ me: null, role: "viewer" });
export const useMe = () => useContext(MeCtx);
export const canEdit = (role: string) => role === "admin" || role === "analyst";

const NAV = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/portfolio", label: "Portfolio" },
  { href: "/projects", label: "Projects" },
  { href: "/alerts", label: "Alerts" },
  { href: "/exceptions", label: "Exceptions" },
  { href: "/watch", label: "Supply chain" },
  { href: "/policies", label: "Policies" },
  { href: "/rules", label: "Rule catalog" },
  { href: "/settings", label: "Settings" },
];

export default function Shell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const path = usePathname();
  const [me, setMe] = useState<Me | null>(null);
  const [dark, setDark] = useState(false);

  useEffect(() => {
    if (!getToken()) { router.replace("/login"); return; }
    api.get<Me>("/api/auth/me").then((m) => {
      if (!getOrg() && m.organizations[0]) setOrg(m.organizations[0].id);
      setMe(m);
    }).catch(() => router.replace("/login"));
    try { setDark(localStorage.getItem("pt_theme") === "dark"); } catch { /* ignore */ }
  }, [router]);

  useEffect(() => {
    document.documentElement.setAttribute("data-bs-theme", dark ? "dark" : "light");
    try { localStorage.setItem("pt_theme", dark ? "dark" : "light"); } catch { /* ignore */ }
  }, [dark]);

  const org = me?.organizations.find((o) => o.id === getOrg()) || me?.organizations[0];
  const logout = () => { setToken(null); setOrg(null); router.replace("/login"); };

  return (
    <MeCtx.Provider value={{ me, role: org?.role || "viewer" }}>
      <nav className="navbar navbar-expand-xl pt-nav sticky-top">
        <div className="container-xl">
          <Link className="navbar-brand fw-bold d-flex align-items-center gap-2" href="/dashboard">
            <span className="pt-logo" aria-hidden>◆</span> PipelineTrust
          </Link>
          <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav" aria-label="Toggle navigation"
            onClick={() => document.getElementById("nav")?.classList.toggle("show")}>
            <span className="navbar-toggler-icon" />
          </button>
          <div className="collapse navbar-collapse" id="nav">
            <ul className="navbar-nav me-auto">
              {NAV.map((n) => (
                <li className="nav-item" key={n.href}>
                  <Link className={`nav-link text-nowrap px-xl-2 ${path?.startsWith(n.href) ? "active" : ""}`} href={n.href}>{n.label}</Link>
                </li>
              ))}
            </ul>
            <div className="d-flex align-items-center gap-2 small">
              <button className="btn btn-sm btn-outline-light" onClick={() => setDark(!dark)} aria-label="Toggle dark mode">{dark ? "☀" : "☾"}</button>
              {org && <span className="text-white-50 text-nowrap" title={me?.email}>{org.name} · <span className="text-white">{org.role}</span></span>}
              <button className="btn btn-sm btn-light text-nowrap" onClick={logout} title={me?.email ? `Signed in as ${me.email}` : undefined}>Sign out</button>
            </div>
          </div>
        </div>
      </nav>
      <main className="container-xl py-4">{me ? children : <Loading />}</main>
    </MeCtx.Provider>
  );
}
