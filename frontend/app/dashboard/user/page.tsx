"use client";

import { useEffect, useState } from "react";
import Navbar from "@/components/Navbar";
import ProtectedRoute from "@/components/ProtectedRoute";
import StatusBadge from "@/components/StatusBadge";
import Link from "next/link";
import { useAuth } from "@/context/AuthContext";
import { apiClient, extractErrorMessage } from "@/lib/api";
import { Wallet, KeyRound, History, Settings, Sparkles } from "lucide-react";

interface CredentialOut {
  id: string;
  credential_type: string;
  status: string;
  issued_at: string;
  expires_at: string | null;
  claims_commitment: string;
}

interface ConsentOut {
  id: string;
  requested_scopes: string[];
  purpose: string;
  status: string;
  requested_at: string;
}

const PREDICATES_BY_TYPE: Record<string, string[]> = {
  age_verification: ["age_gte_18", "age_gte_21"],
  student_status: ["is_student_eq_true"],
  employee_status: ["is_employee_eq_true"],
  kyc_validity: ["kyc_valid_eq_true"],
};

function UserDashboardContent() {
  const { user, refreshSession } = useAuth();
  const [tab, setTab] = useState<"wallet" | "proof" | "consent" | "settings">("wallet");
  const [credentials, setCredentials] = useState<CredentialOut[]>([]);
  const [consents, setConsents] = useState<ConsentOut[]>([]);
  const [walletMeta, setWalletMeta] = useState<{ did: string | null; credential_count: number; active_credential_count: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedCredentialId, setSelectedCredentialId] = useState("");
  const [selectedPredicate, setSelectedPredicate] = useState("");
  const [proofResult, setProofResult] = useState<any>(null);
  const [generatingProof, setGeneratingProof] = useState(false);

  const [mfaUri, setMfaUri] = useState<string | null>(null);
  const [mfaManualKey, setMfaManualKey] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaMessage, setMfaMessage] = useState<string | null>(null);
  const [mfaLoading, setMfaLoading] = useState(false);

  async function loadAll() {
    setLoading(true);
    setError(null);
    try {
      const [meRes, credsRes, consentRes] = await Promise.all([
        apiClient.get("/wallet/me"),
        apiClient.get("/wallet/credentials"),
        apiClient.get("/consent/history"),
      ]);
      setWalletMeta(meRes.data);
      setCredentials(credsRes.data);
      setConsents(consentRes.data);
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAll();
  }, []);

  const selectedCredential = credentials.find((c) => c.id === selectedCredentialId);
  const availablePredicates = selectedCredential ? PREDICATES_BY_TYPE[selectedCredential.credential_type] || [] : [];

  async function handleGenerateProof() {
    if (!selectedCredentialId || !selectedPredicate) return;
    setGeneratingProof(true);
    setProofResult(null);
    setError(null);
    try {
      const { data } = await apiClient.post("/wallet/generate-proof", {
        credential_id: selectedCredentialId,
        claim_predicate: selectedPredicate,
      });
      setProofResult(data);
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setGeneratingProof(false);
    }
  }

  async function respondToConsent(consentId: string, approve: boolean) {
    try {
      await apiClient.post("/consent/respond", { consent_id: consentId, approve });
      loadAll();
    } catch (err) {
      setError(extractErrorMessage(err));
    }
  }

  const tabs = [
    { id: "wallet", label: "Wallet", icon: Wallet },
    { id: "proof", label: "Generate Proof", icon: KeyRound },
    { id: "consent", label: "Consent History", icon: History },
    { id: "settings", label: "Security Settings", icon: Settings },
  ] as const;

  return (
    <main>
      <Navbar />
      <div className="max-w-6xl mx-auto px-6 py-10">
        <h1 className="text-2xl font-semibold text-gray-900 mb-1">Your Wallet</h1>
        <p className="text-gray-500 mb-4">Manage your credentials, proofs, and consent — all under your control.</p>
        <Link
          href="/dashboard/user/verify"
          className="inline-flex items-center gap-2 text-sm text-brand-600 font-medium mb-8 hover:underline"
        >
          <Sparkles className="w-4 h-4" />
          Run identity verification (document + face + liveness)
        </Link>

        {error && <div className="bg-red-50 text-red-700 text-sm rounded-lg px-3 py-2 mb-6">{error}</div>}

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

        {loading ? (
          <p className="text-gray-400 text-sm">Loading...</p>
        ) : (
          <>
            {tab === "wallet" && (
              <div>
                <div className="grid sm:grid-cols-3 gap-4 mb-8">
                  <div className="card">
                    <p className="text-xs text-gray-400 mb-1">Decentralized ID</p>
                    <p className="text-sm font-mono truncate">{walletMeta?.did || "—"}</p>
                  </div>
                  <div className="card">
                    <p className="text-xs text-gray-400 mb-1">Total Credentials</p>
                    <p className="text-2xl font-semibold">{walletMeta?.credential_count ?? 0}</p>
                  </div>
                  <div className="card">
                    <p className="text-xs text-gray-400 mb-1">Active Credentials</p>
                    <p className="text-2xl font-semibold">{walletMeta?.active_credential_count ?? 0}</p>
                  </div>
                </div>

                <div className="card overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-gray-400 border-b border-gray-100">
                        <th className="pb-2">Type</th>
                        <th className="pb-2">Status</th>
                        <th className="pb-2">Issued</th>
                        <th className="pb-2">Expires</th>
                        <th className="pb-2">Commitment</th>
                      </tr>
                    </thead>
                    <tbody>
                      {credentials.map((c) => (
                        <tr key={c.id} className="border-b border-gray-50 last:border-0">
                          <td className="py-3">{c.credential_type.replace(/_/g, " ")}</td>
                          <td className="py-3">
                            <StatusBadge status={c.status} />
                          </td>
                          <td className="py-3 text-gray-500">{new Date(c.issued_at).toLocaleDateString()}</td>
                          <td className="py-3 text-gray-500">{c.expires_at ? new Date(c.expires_at).toLocaleDateString() : "—"}</td>
                          <td className="py-3 font-mono text-xs text-gray-400">{c.claims_commitment.slice(0, 12)}...</td>
                        </tr>
                      ))}
                      {credentials.length === 0 && (
                        <tr>
                          <td colSpan={5} className="py-6 text-center text-gray-400">
                            No credentials yet. Ask an approved issuer to issue one to your account.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {tab === "proof" && (
              <div className="card max-w-xl">
                <div className="flex items-center gap-2 mb-4 text-brand-700">
                  <Sparkles className="w-5 h-5" />
                  <h3 className="font-semibold">Proof Generation Wizard</h3>
                </div>

                <label className="block text-sm font-medium text-gray-700 mb-1">Credential</label>
                <select
                  className="input-field mb-4"
                  value={selectedCredentialId}
                  onChange={(e) => {
                    setSelectedCredentialId(e.target.value);
                    setSelectedPredicate("");
                    setProofResult(null);
                  }}
                >
                  <option value="">Select a credential...</option>
                  {credentials
                    .filter((c) => c.status === "active")
                    .map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.credential_type.replace(/_/g, " ")} — issued {new Date(c.issued_at).toLocaleDateString()}
                      </option>
                    ))}
                </select>

                <label className="block text-sm font-medium text-gray-700 mb-1">Claim to prove</label>
                <select
                  className="input-field mb-6"
                  value={selectedPredicate}
                  onChange={(e) => setSelectedPredicate(e.target.value)}
                  disabled={!selectedCredentialId}
                >
                  <option value="">Select a predicate...</option>
                  {availablePredicates.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>

                <button
                  onClick={handleGenerateProof}
                  disabled={!selectedCredentialId || !selectedPredicate || generatingProof}
                  className="btn-primary w-full mb-4"
                >
                  {generatingProof ? "Generating zero-knowledge proof..." : "Generate Proof"}
                </button>

                {proofResult && (
                  <div className="bg-gray-50 border border-gray-100 rounded-lg p-4 text-xs font-mono break-all">
                    <p className="mb-2 text-gray-500 font-sans text-sm">
                      Proof ID: <span className="text-gray-800">{proofResult.zk_proof_id}</span>
                    </p>
                    <p className="text-gray-400">{JSON.stringify(proofResult.public_inputs, null, 2)}</p>
                  </div>
                )}
              </div>
            )}

            {tab === "consent" && (
              <div className="card overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-400 border-b border-gray-100">
                      <th className="pb-2">Scopes</th>
                      <th className="pb-2">Purpose</th>
                      <th className="pb-2">Status</th>
                      <th className="pb-2">Requested</th>
                      <th className="pb-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {consents.map((c) => (
                      <tr key={c.id} className="border-b border-gray-50 last:border-0">
                        <td className="py-3">{c.requested_scopes.join(", ")}</td>
                        <td className="py-3 text-gray-500 max-w-xs truncate">{c.purpose}</td>
                        <td className="py-3">
                          <StatusBadge status={c.status} />
                        </td>
                        <td className="py-3 text-gray-500">{new Date(c.requested_at).toLocaleDateString()}</td>
                        <td className="py-3">
                          {c.status === "pending" && (
                            <div className="flex gap-2">
                              <button onClick={() => respondToConsent(c.id, true)} className="text-xs text-brand-600 font-medium">
                                Approve
                              </button>
                              <button onClick={() => respondToConsent(c.id, false)} className="text-xs text-red-500 font-medium">
                                Deny
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                    {consents.length === 0 && (
                      <tr>
                        <td colSpan={5} className="py-6 text-center text-gray-400">
                          No consent requests yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {tab === "settings" && (
              <div className="card max-w-xl space-y-6">
                <div>
                  <h3 className="font-semibold mb-2">Multi-factor authentication</h3>
                  {user?.mfaEnabled ? (
                    <p className="text-sm text-green-700 bg-green-50 rounded-lg px-3 py-2">MFA is enabled on your account.</p>
                  ) : (
                    <div className="space-y-3">
                      <p className="text-sm text-gray-500">
                        Protect your wallet with TOTP (Google Authenticator, Authy, etc.).
                      </p>
                      {!mfaUri ? (
                        <button
                          className="btn-secondary text-sm"
                          disabled={mfaLoading}
                          onClick={async () => {
                            setMfaLoading(true);
                            setMfaMessage(null);
                            try {
                              const { data } = await apiClient.post("/auth/mfa/setup");
                              setMfaUri(data.provisioning_uri);
                              setMfaManualKey(data.manual_entry_key);
                            } catch (err) {
                              setMfaMessage(extractErrorMessage(err));
                            } finally {
                              setMfaLoading(false);
                            }
                          }}
                        >
                          {mfaLoading ? "Preparing..." : "Set up MFA"}
                        </button>
                      ) : (
                        <div className="space-y-3">
                          <p className="text-xs text-gray-500 break-all font-mono">{mfaManualKey}</p>
                          <input
                            className="input-field"
                            placeholder="6-digit code"
                            maxLength={6}
                            value={mfaCode}
                            onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                          />
                          <button
                            className="btn-primary text-sm"
                            disabled={mfaCode.length !== 6 || mfaLoading}
                            onClick={async () => {
                              setMfaLoading(true);
                              setMfaMessage(null);
                              try {
                                await apiClient.post("/auth/mfa/enable", { otp_code: mfaCode });
                                setMfaMessage("MFA enabled successfully.");
                                setMfaUri(null);
                                await refreshSession();
                              } catch (err) {
                                setMfaMessage(extractErrorMessage(err));
                              } finally {
                                setMfaLoading(false);
                              }
                            }}
                          >
                            Confirm and enable
                          </button>
                        </div>
                      )}
                      {mfaMessage && <p className="text-sm text-gray-600">{mfaMessage}</p>}
                    </div>
                  )}
                </div>
                <div>
                  <h3 className="font-semibold mb-2">Decentralized identity</h3>
                  <p className="text-xs text-gray-400">
                    DID public key algorithm: <span className="font-mono">Ed25519</span>
                  </p>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </main>
  );
}

export default function UserDashboardPage() {
  return (
    <ProtectedRoute allowedRoles={["user"]}>
      <UserDashboardContent />
    </ProtectedRoute>
  );
}
