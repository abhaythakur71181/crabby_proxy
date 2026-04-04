import {
  LayoutDashboard, Cable, Users, FolderOpen, KeyRound, BarChart3,
  CheckCircle, Landmark, ScrollText, Settings, HeartPulse, LogOut,
} from 'lucide-react';
import { NavLink } from '@/components/NavLink';
import { useLocation } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { Badge } from '@/components/ui/badge';
import {
  Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent,
  SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarFooter, useSidebar,
} from '@/components/ui/sidebar';
import { cn } from '@/lib/utils';

const navItems = [
  { title: 'Dashboard', url: '/dashboard', icon: LayoutDashboard },
  { title: 'Connections', url: '/connections', icon: Cable, badge: true },
  { title: 'Users', url: '/users', icon: Users },
  { title: 'Groups', url: '/groups', icon: FolderOpen },
  { title: 'API Keys', url: '/api-keys', icon: KeyRound },
  { title: 'Usage & Quotas', url: '/usage', icon: BarChart3 },
  { title: 'Approvals', url: '/approvals', icon: CheckCircle },
  { title: 'Tunnels', url: '/tunnels', icon: Landmark },
  { title: 'Audit Log', url: '/audit-log', icon: ScrollText },
  { title: 'Configuration', url: '/configuration', icon: Settings },
  { title: 'System Health', url: '/system-health', icon: HeartPulse },
];

export function AppSidebar() {
  const { state } = useSidebar();
  const collapsed = state === 'collapsed';
  const location = useLocation();
  const { user, logout } = useAuth();

  const roleBadgeColor: Record<string, string> = {
    root_admin: 'bg-red-500/20 text-red-400 border-red-500/30',
    admin: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    user: 'bg-muted text-muted-foreground border-border',
  };

  return (
    <Sidebar collapsible="icon" className="border-r border-sidebar-border bg-sidebar">
      <div className={cn('flex items-center gap-2 px-4 py-4 border-b border-sidebar-border', collapsed && 'justify-center px-2')}>
        <span className="text-2xl">🦀</span>
        {!collapsed && (
          <div className="flex flex-col">
            <span className="font-semibold text-sm text-sidebar-foreground">Crabby Proxy</span>
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 w-fit border-primary/30 text-primary">v0.1.0</Badge>
          </div>
        )}
      </div>
      <SidebarContent className="px-2 py-2">
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map(item => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton asChild>
                    <NavLink
                      to={item.url}
                      end={item.url === '/dashboard'}
                      className="hover:bg-sidebar-accent/50 rounded-md px-3 py-2 text-sm"
                      activeClassName="bg-sidebar-accent text-primary font-medium"
                    >
                      <item.icon className="h-4 w-4 mr-2 shrink-0" />
                      {!collapsed && <span>{item.title}</span>}
                    </NavLink>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter className="border-t border-sidebar-border p-3">
        {user && (
          <div className={cn('flex items-center gap-2', collapsed && 'justify-center')}>
            <div className="h-8 w-8 rounded-full bg-primary/20 flex items-center justify-center text-primary text-sm font-bold shrink-0">
              {user.username[0].toUpperCase()}
            </div>
            {!collapsed && (
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-sidebar-foreground truncate">{user.username}</p>
                <span className={cn('inline-flex items-center px-1.5 py-0 rounded text-[10px] font-medium border', roleBadgeColor[user.role] || '')}>
                  {user.role}
                </span>
              </div>
            )}
            {!collapsed && (
              <button onClick={logout} className="text-muted-foreground hover:text-foreground p-1" title="Logout">
                <LogOut className="h-4 w-4" />
              </button>
            )}
          </div>
        )}
      </SidebarFooter>
    </Sidebar>
  );
}
