"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import Navbar from "@/components/Navbar";
import { useAuth, extractErrorMessage } from "@/context/AuthContext";
import { ShieldCheck } from "lucide-react";

const roleHome: Record<string, string> = {
  user: "/dashboard/user",
  issuer: "/dashboard/issuer",
  verifier: "/dashboard/verifier",
  admin: "/dashboard/admin",
};

export default function LoginPage() {
  const { login, verifyOtp } = useAuth();
  const router = useRouter();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function goToDashboard(role: string) {
    router.push(roleHome[role] || "/dashboard/user");
  }

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const result = await login(email, password);
      if (result.otpRequired && result.challengeToken) {
        setChallengeToken(result.challengeToken);
      } else if (result.role) {
        goToDashboard(result.role);
      }
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleOtp(e: React.FormEvent) {
    e.preventDefault();
    if (!challengeToken) return;
    setError(null);
    setSubmitting(true);
    try {
      await verifyOtp(challengeToken, otpCode);
      const { data } = await (await import("@/lib/api")).apiClient.get("/auth/me");
      goToDashboard(data.role);
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main>
      <Navbar />
      <div className="max-w-md mx-auto px-6 py-16">
        <div className="text-center mb-8">
          <ShieldCheck className="w-8 h-8 text-brand-600 mx-auto mb-3" />
          <h1 className="text-2xl font-semibold text-gray-900">Welcome back</h1>
        </div>

        <div className="card">
          {error && (
            <div className="bg-red-50 text-red-700 text-sm rounded-lg px-3 py-2 mb-4">{error}</div>
          )}

          {!challengeToken ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                <input
                  type="email"
                  required
                  className="input-field"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                <input
                  type="password"
                  required
                  className="input-field"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
              <button type="submit" disabled={submitting} className="btn-primary w-full">
                {submitting ? "Signing in..." : "Sign in"}
              </button>
            </form>
          ) : (
            <form onSubmit={handleOtp} className="space-y-4">
              <p className="text-sm text-gray-500">Enter the 6-digit code from your authenticator app.</p>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                required
                className="input-field text-center tracking-widest text-lg"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ""))}
              />
              <button type="submit" disabled={submitting} className="btn-primary w-full">
                {submitting ? "Verifying..." : "Verify"}
              </button>
            </form>
          )}

          <p className="text-sm text-gray-500 text-center mt-6">
            Don&apos;t have an account?{" "}
            <Link href="/register" className="text-brand-600 font-medium">
              Create one
            </Link>
          </p>
        </div>
      </div>
    </main>
  );
}
