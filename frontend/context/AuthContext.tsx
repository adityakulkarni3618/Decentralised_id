"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { apiClient, extractErrorMessage } from "@/lib/api";

export type Role = "user" | "issuer" | "verifier" | "admin";

interface AuthUser {
  userId: string;
  email: string;
  role: Role;
  mfaEnabled: boolean;
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<{ otpRequired: boolean; challengeToken?: string; role?: Role }>;
  verifyOtp: (challengeToken: string, code: string) => Promise<void>;
  register: (email: string, password: string, fullName: string, role: Role) => Promise<void>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

function mapUser(data: { user_id: string; email: string; role: Role; mfa_enabled?: boolean }): AuthUser {
  return {
    userId: data.user_id,
    email: data.email,
    role: data.role,
    mfaEnabled: Boolean(data.mfa_enabled),
  };
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  const refreshSession = useCallback(async () => {
    try {
      const { data } = await apiClient.get("/auth/me");
      setUser(mapUser(data));
    } catch {
      setUser(null);
    }
  }, []);

  useEffect(() => {
    refreshSession().finally(() => setLoading(false));
  }, [refreshSession]);

  const login = useCallback(async (email: string, password: string) => {
    const { data } = await apiClient.post("/auth/login", { email, password });
    if (data.otp_required) {
      return { otpRequired: true, challengeToken: data.otp_challenge_token };
    }
    setUser(mapUser(data));
    return { otpRequired: false, role: data.role };
  }, []);

  const verifyOtp = useCallback(async (challengeToken: string, code: string) => {
    const { data } = await apiClient.post("/auth/verify-otp", {
      otp_challenge_token: challengeToken,
      otp_code: code,
    });
    setUser(mapUser(data));
  }, []);

  const register = useCallback(async (email: string, password: string, fullName: string, role: Role) => {
    await apiClient.post("/auth/register", { email, password, full_name: fullName, role });
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiClient.post("/auth/logout");
    } catch {}
    setUser(null);
    router.push("/login");
  }, [router]);

  return (
    <AuthContext.Provider value={{ user, loading, login, verifyOtp, register, logout, refreshSession }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}

export { extractErrorMessage };
