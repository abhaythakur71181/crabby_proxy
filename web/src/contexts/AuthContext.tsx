import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import { api } from '@/lib/api';
import type { UserRole } from '@/lib/types';

interface AuthUser {
  id: number;
  username: string;
  role: UserRole;
  token: string;
}

interface AuthContextType {
  user: AuthUser | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  hasRole: (...roles: UserRole[]) => boolean;
}

const AuthContext = createContext<AuthContextType>(null!);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(() => {
    try {
      const stored = localStorage.getItem('crabby_auth');
      return stored ? JSON.parse(stored) : null;
    } catch { return null; }
  });

  const login = useCallback(async (username: string, password: string) => {
    const res = await api.login(username, password);
    const authUser: AuthUser = {
      id: res.user_id,
      username: res.username,
      role: res.role,
      token: res.token,
    };
    localStorage.setItem('crabby_auth', JSON.stringify(authUser));
    setUser(authUser);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('crabby_auth');
    setUser(null);
  }, []);

  const hasRole = useCallback((...roles: UserRole[]) => {
    if (!user) return false;
    return roles.includes(user.role);
  }, [user]);

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated: !!user, hasRole }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
