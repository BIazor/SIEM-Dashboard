import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { User } from "../types";
import { api, clearSession, getStoredUser, storeUser } from "./api";

interface AuthContextValue {
  user: User | null;
  ready: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(getStoredUser);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let canceled = false;
    // The session lives in an httpOnly cookie, so the only way to know whether it
    // is still valid is to ask the API.
    api
      .me()
      .then((current) => {
        if (!canceled) {
          setUser(current);
          storeUser(current);
        }
      })
      .catch(() => {
        if (!canceled) {
          clearSession();
          setUser(null);
        }
      })
      .finally(() => {
        if (!canceled) setReady(true);
      });
    return () => {
      canceled = true;
    };
  }, []);

  useEffect(() => {
    const onExpired = () => setUser(null);
    window.addEventListener("aegis:session-expired", onExpired);
    return () => window.removeEventListener("aegis:session-expired", onExpired);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const result = await api.login(email, password);
    storeUser(result.user);
    setUser(result.user);
  }, []);

  const logout = useCallback(() => {
    // Revoke server-side first, then drop local state even if the call fails.
    void api.logout().catch(() => undefined);
    clearSession();
    setUser(null);
  }, []);

  const value = useMemo(() => ({ user, ready, login, logout }), [user, ready, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}

export function canInvestigate(role: string | undefined): boolean {
  return role === "admin" || role === "analyst";
}

export function canApprove(role: string | undefined): boolean {
  return role === "admin" || role === "approver";
}
