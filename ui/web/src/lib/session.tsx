import { createContext, useContext, type ReactNode } from "react";
import type { Me } from "../api/types";

const SessionContext = createContext<Me | null>(null);

export function SessionProvider({ me, children }: { me: Me; children: ReactNode }) {
  return <SessionContext.Provider value={me}>{children}</SessionContext.Provider>;
}

export function useSession(): Me {
  const me = useContext(SessionContext);
  if (!me) throw new Error("useSession used outside a signed-in page");
  return me;
}

/** Whether the signed-in user holds a permission. The server enforces it too;
 *  this only decides what to show. */
export function can(me: Me, permission: string): boolean {
  return me.permissions.includes(permission);
}
