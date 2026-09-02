import { Link, Outlet } from '@tanstack/react-router'

const activeProps = { 'aria-current': 'page' as const }

export function AppLayout() {
  return (
    <>
      <header className="site-header">
        <nav aria-label="Primary navigation">
          <Link className="brand" to="/">JEDI Hiring Legal Atlas</Link>
          <div className="nav-links">
            <Link activeOptions={{ exact: true }} activeProps={activeProps} to="/">Legal map</Link>
            <Link activeProps={activeProps} to="/sources">Sources</Link>
            <Link activeProps={activeProps} to="/countries">Countries</Link>
          </div>
        </nav>
      </header>
      <Outlet />
    </>
  )
}
