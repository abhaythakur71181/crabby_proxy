
# Crabby Proxy Admin Dashboard — Full Build Plan

## Design System Foundation
- **Dark theme** default with deep navy/charcoal (#0a0e1a, #111827), cyan accents (#06b6d4, #22d3ee), amber warnings (#f59e0b)
- Glassmorphism cards with backdrop-blur, monospace for technical data (JetBrains Mono via Google Fonts), Inter for UI text
- Custom CSS variables for the color palette layered on top of shadcn's system
- Micro-animations: animated counters, pulsing status dots, gauge fills

## Global Layout
- **Collapsible sidebar** (shadcn Sidebar) with all 11 nav items, crab logo, version badge, user avatar + role, logout
- **Top bar**: breadcrumbs, global search input, notification bell, theme toggle
- Responsive: sidebar collapses to icon-only on smaller screens

## API Service Layer
- Central `apiClient` with JWT auth header injection, error interceptor (401→login redirect, 403→toast, 429→retry countdown)
- Mock data service for all 40 endpoints with realistic proxy data (IPs, UUIDs, bandwidth numbers, protocols)
- Easy swap: change base URL and remove mocks to connect real backend

## Pages (all 12)

### 1. Login Page
- Centered glassmorphism card on dark gradient background, glowing crab icon
- Username/password fields with validation, password visibility toggle
- JWT stored in localStorage, role-based redirect

### 2. Dashboard
- 6 stat cards (Uptime, Active Connections, Total Connections, Bandwidth 24h, Total Users, Active Tunnels) with animated counters
- Bandwidth sent/received dual gauge bars
- Top Users table (last 24h) with rank, user link, bandwidth, connections
- System status indicator, auto-refresh polling

### 3. Connections
- **Active list**: sortable table with protocol badges (color-coded per protocol), state badges, byte counts, relative timestamps
- Protocol filter dropdown, search by IP/target
- **Live feed tab**: simulated WebSocket updates, pulsing connection dots visualization

### 4. User Management
- **List**: paginated table with role badges, active toggle, search/filter
- **Create User modal**: form with validation (root_admin only)
- **Detail page** with 7 tabs: Profile (editable), API Keys, Usage, Quota, Groups, Sessions, Approvals
- Role-based permission checks on all actions

### 5. API Keys (within User Detail)
- List with key prefix (monospace), status badge, last used
- Create key → one-time reveal modal with warning banner + copy button
- Revoke with confirmation dialog

### 6. Usage & Quotas
- Per-user stats cards with period selector (1d/7d/30d/90d/all-time)
- Recent usage records table (connection details, duration, status)
- Circular quota gauge with color transitions (green→yellow→red)
- System usage summary page (admin only) with top users leaderboard bar chart

### 7. Groups
- Groups list table with member count
- Group detail: members table with add/remove member (user picker)
- Create/delete group modals

### 8. Approvals
- Approvals table with IP, duration, reason, expiry countdown
- Create approval form (user picker, IP, duration, reason)
- Terminate with required reason field

### 9. Tunnels
- Tunnels list with service type badges (color per type), port, status
- Create tunnel form with service type dropdown, optional port, target address
- Close tunnel with confirmation

### 10. Configuration
- Read-only config display organized by section (Server, Auth, Features)
- Feature toggle indicators (visual only, not editable)
- Reload Config button with confirmation dialog (admin only)

### 11. Audit Log
- Paginated table with expandable detail rows
- Filters: user dropdown, action search, date range
- Full pagination controls with total count

### 12. System Health
- Basic + deep health status cards (Database, State Backend, DNS Cache) with green/red indicators
- **Charts (Chart.js)**: Active connections by protocol (donut), request rate (line), bandwidth (line), auth failures (bar), connection duration percentiles, upstream latency percentiles, IP filter actions, rate limit sparklines
- Draining mode amber banner when active

## Reusable Components
- StatCard, DataTable (sortable/filterable/paginated), ProtocolBadge, StatusDot (pulsing), CopyButton, ConfirmDialog, CircularGauge, EmptyState (crab illustration), SearchInput (debounced)
- Utility functions: bytes→human readable, seconds→duration, relative timestamps, UUID truncation

## Auth & Routing
- Protected route wrapper checking JWT + role
- Role-based UI rendering (hide/show elements per permission matrix)
- Auto-logout on token expiry with "Session expired" modal
- Login redirect on 401 responses
