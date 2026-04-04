import { useLocation, Link } from 'react-router-dom';
import { SidebarTrigger } from '@/components/ui/sidebar';
import { ChevronRight } from 'lucide-react';

const routeNames: Record<string, string> = {
  '/dashboard': 'Dashboard',
  '/connections': 'Connections',
  '/users': 'Users',
  '/groups': 'Groups',
  '/api-keys': 'API Keys',
  '/usage': 'Usage & Quotas',
  '/approvals': 'Approvals',
  '/tunnels': 'Tunnels',
  '/audit-log': 'Audit Log',
  '/configuration': 'Configuration',
  '/system-health': 'System Health',
};

export function TopBar() {
  const location = useLocation();
  const pathParts = location.pathname.split('/').filter(Boolean);

  const breadcrumbs = pathParts.map((part, i) => {
    const path = '/' + pathParts.slice(0, i + 1).join('/');
    const name = routeNames[path] || part.replace(/[-_]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    return { path, name };
  });

  return (
    <header className="h-12 flex items-center border-b border-border bg-background/80 backdrop-blur-sm px-4 gap-3 shrink-0">
      <SidebarTrigger className="text-muted-foreground hover:text-foreground" />
      <nav className="flex items-center gap-1 text-sm">
        <Link to="/dashboard" className="text-muted-foreground hover:text-foreground">Dashboard</Link>
        {breadcrumbs.slice(1).map(b => (
          <span key={b.path} className="flex items-center gap-1">
            <ChevronRight className="h-3 w-3 text-muted-foreground" />
            <Link to={b.path} className="text-foreground font-medium">{b.name}</Link>
          </span>
        ))}
      </nav>
    </header>
  );
}
