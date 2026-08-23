"use client";

import { useEffect, useState } from "react";
import Navbar from "@/components/Navbar";
import ProtectedRoute from "@/components/ProtectedRoute";
import StatusBadge from "@/components/StatusBadge";
import SearchFilterToolbar from "@/components/SearchFilterToolbar";
import { apiClient, extractErrorMessage } from "@/lib/api";
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip } from "recharts";
import { FilePlus2, List, Gauge } from "lucide-react";

interface IssuerCredentialOut {
  id: string;
  holder_id: string;
  credential_type: string;
  status: string;
  issued_at: string;
  expires_at: string | null;
  blockchain_tx_hash: string | null;
}

interface DashboardStats {
  organization_name: string;
  is_approved: boolean;
  total_issued: number;
  total_active: number;
  total_revoked: number;
  issued_last_30_days: number;
}

const CREDENTIAL_TYPES = ["age_verification", "student_status", "employee_status", "kyc_validity"];

function IssuerDashboardContent() {
  const [tab, setTab] = useState<"dashboard" | "issue" | "issued">("dashboard");
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [issued, setIssued] = useState<IssuerCredentialOut[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");

  const [holderEmail, setHolderEmail] = useState("");
  const [credentialType, setCredentialType] = useState(CREDENTIAL_TYPES[0]);
  const [claimsText, setClaimsText] = useState('{\n  "date_of_birth": "2000-01-01",\n  "age": "26"\n}');
  const [issuing, setIssuing] = useState(false);

  async function loadAll() {
    setError(null);
    try {
      const [statsRes, issuedRes] = await Promise.all([
        apiClient.get("/issuer/dashboard"),
        apiClient.get("/issuer/credentials"),
      ]);
      setStats(statsRes.data);
      setIssued(issuedRes.data);
    } catch (err) {
      setError(extractErrorMessage(err));
    }
  }

  useEffect(() => {
    loadAll();
  }, []);

  async function handleIssue(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    let claims;
    try {
      claims = JSON.parse(claimsText);
    } catch {
      setError("Claims must be valid JSON.");
      return;
    }
    setIssuing(true);
    try {
      const { data } = await apiClient.post("/issuer/credentials", {
        holder_email: holderEmail,
        credential_type: credentialType,
        claims,
      });
      setSuccess(`Credential issued: ${data.credential_id}`);
      setHolderEmail("");
      loadAll();
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setIssuing(false);
    }
  }

  async function handleRevoke(credentialId: string) {
    const reason = window.prompt("Reason for revocation:");
    if (!reason) return;
    try {
      await apiClient.post("/issuer/revoke", { credential_id: credentialId, reason });
      loadAll();
    } catch (err) {
      setError(extractErrorMessage(err));
    }
  }

  async function handleAnchor(credentialId: string) {
    setError(null);
    setSuccess(null);
    try {
      const { data } = await apiClient.post("/blockchain/anchor-credential", { credential_id: credentialId });
      setSuccess(`Anchored on-chain: ${data.tx_hash}`);
      loadAll();
    } catch (err) {
      setError(extractErrorMessage(err));
    }
  }

  async function handleAnchorRevocation(credentialId: string) {
    setError(null);
    try {
      const { data } = await apiClient.post("/blockchain/anchor-revocation", { credential_id: credentialId });
      setSuccess(`Revocation anchored: ${data.tx_hash}`);
      loadAll();
    } catch (err) {
      setError(extractErrorMessage(err));
    }
  }

  const filteredIssued = issued.filter((c) => {
    const matchesSearch = c.credential_type.toLowerCase().includes(search.toLowerCase()) || c.holder_id.includes(search);
    const matchesStatus = statusFilter === "all" || c.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const chartData = stats
    ? [
        { name: "Active", value: stats.total_active },
        { name: "Revoked", value: stats.total_revoked },
        { name: "Last 30d", value: stats.issued_last_30_days },
      ]
    : [];

  const tabs = [
    { id: "dashboard", label: "Dashboard", icon: Gauge },
    { id: "issue", label: "Issue Credential", icon: FilePlus2 },
    { id: "issued", label: "Issued List", icon: List },
  ] as const;

  return (
    <main>
      <Navbar />
      <div className="max-w-6xl mx-auto px-6 py-10">
        <h1 className="text-2xl font-semibold text-gray-900 mb-1">Issuer Console</h1>
        <p className="text-gray-500 mb-8">{stats?.organization_name}</p>

        {error && <div className="bg-red-50 text-red-700 text-sm rounded-lg px-3 py-2 mb-6">{error}</div>}
        {success && <div className="bg-green-50 text-green-700 text-sm rounded-lg px-3 py-2 mb-6">{success}</div>}
        {stats && !stats.is_approved && (
          <div className="bg-yellow-50 text-yellow-800 text-sm rounded-lg px-3 py-2 mb-6">
            Your issuer account is pending admin approval. You cannot issue credentials until approved.
          </div>
        )}

        <div className="flex gap-2 mb-8 flex-wrap">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium ${
                tab === t.id ? "bg-brand-600 text-white" : "bg-white border border-gray-200 text-gray-600"
              }`}
            >
              <t.icon className="w-4 h-4" />
              {t.label}
            </button>
          ))}
        </div>

        {tab === "dashboard" && stats && (
          <div>
            <div className="grid sm:grid-cols-4 gap-4 mb-8">
              <div className="card">
                <p className="text-xs text-gray-400 mb-1">Total Issued</p>
                <p className="text-2xl font-semibold">{stats.total_issued}</p>
              </div>
              <div className="card">
                <p className="text-xs text-gray-400 mb-1">Active</p>
                <p className="text-2xl font-semibold text-green-600">{stats.total_active}</p>
              </div>
              <div className="card">
                <p className="text-xs text-gray-400 mb-1">Revoked</p>
                <p className="text-2xl font-semibold text-red-500">{stats.total_revoked}</p>
              </div>
              <div className="card">
                <p className="text-xs text-gray-400 mb-1">Issued (30d)</p>
                <p className="text-2xl font-semibold">{stats.issued_last_30_days}</p>
              </div>
            </div>

            <div className="card">
              <p className="text-sm font-medium text-gray-700 mb-4">Credential Overview</p>
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={chartData}>
                  <XAxis dataKey="name" fontSize={12} />
                  <YAxis fontSize={12} allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#3a58f5" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {tab === "issue" && (
          <form onSubmit={handleIssue} className="card max-w-xl space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Holder email</label>
              <input
                type="email"
                required
                className="input-field"
                value={holderEmail}
                onChange={(e) => setHolderEmail(e.target.value)}
                placeholder="recipient@example.com"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Credential type</label>
              <select className="input-field" value={credentialType} onChange={(e) => setCredentialType(e.target.value)}>
                {CREDENTIAL_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Claims (JSON)</label>
              <textarea
                className="input-field font-mono text-xs h-32"
                value={claimsText}
                onChange={(e) => setClaimsText(e.target.value)}
              />
            </div>
            <button type="submit" disabled={issuing} className="btn-primary w-full">
              {issuing ? "Issuing..." : "Issue Credential"}
            </button>
          </form>
        )}

        {tab === "issued" && (
          <div className="card">
            <SearchFilterToolbar
              searchValue={search}
              onSearchChange={setSearch}
              searchPlaceholder="Search by type or holder id..."
              filterValue={statusFilter}
              onFilterChange={setStatusFilter}
              filterOptions={[
                { label: "All statuses", value: "all" },
                { label: "Active", value: "active" },
                { label: "Revoked", value: "revoked" },
                { label: "Expired", value: "expired" },
              ]}
            />
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-400 border-b border-gray-100">
                    <th className="pb-2">Holder</th>
                    <th className="pb-2">Type</th>
                    <th className="pb-2">Status</th>
                    <th className="pb-2">Issued</th>
                    <th className="pb-2">On-chain</th>
                    <th className="pb-2"></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredIssued.map((c) => (
                    <tr key={c.id} className="border-b border-gray-50 last:border-0">
                      <td className="py-3 font-mono text-xs">{c.holder_id.slice(0, 8)}...</td>
                      <td className="py-3">{c.credential_type.replace(/_/g, " ")}</td>
                      <td className="py-3">
                        <StatusBadge status={c.status} />
                      </td>
                      <td className="py-3 text-gray-500">{new Date(c.issued_at).toLocaleDateString()}</td>
                      <td className="py-3 font-mono text-xs text-gray-400">
                        {c.blockchain_tx_hash ? `${c.blockchain_tx_hash.slice(0, 10)}…` : "—"}
                      </td>
                      <td className="py-3">
                        <div className="flex gap-2 flex-wrap">
                          {c.status === "active" && !c.blockchain_tx_hash && (
                            <button onClick={() => handleAnchor(c.id)} className="text-xs text-brand-600 font-medium">
                              Anchor
                            </button>
                          )}
                          {c.status === "active" && (
                            <button onClick={() => handleRevoke(c.id)} className="text-xs text-red-500 font-medium">
                              Revoke
                            </button>
                          )}
                          {c.status === "revoked" && (
                            <button onClick={() => handleAnchorRevocation(c.id)} className="text-xs text-brand-600 font-medium">
                              Anchor revocation
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {filteredIssued.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-6 text-center text-gray-400">
                        No credentials found.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}

export default function IssuerDashboardPage() {
  return (
    <ProtectedRoute allowedRoles={["issuer"]}>
      <IssuerDashboardContent />
    </ProtectedRoute>
  );
}
