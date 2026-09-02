import React from 'react'
import ReactDOM from 'react-dom/client'
import {
  RouterProvider,
  createRootRoute,
  createRoute,
  createRouter,
} from '@tanstack/react-router'
import { AppLayout } from './components/AppLayout'
import { CountriesPage } from './pages/CountriesPage'
import { LegalMapPage } from './pages/LegalMapPage'
import { RequirementDetailPage } from './pages/RequirementDetailPage'
import { SourcesPage } from './pages/SourcesPage'
import './styles.css'

const rootRoute = createRootRoute({ component: AppLayout })
const legalMapRoute = createRoute({ getParentRoute: () => rootRoute, path: '/', component: LegalMapPage })
const sourcesRoute = createRoute({ getParentRoute: () => rootRoute, path: '/sources', component: SourcesPage })
const countriesRoute = createRoute({ getParentRoute: () => rootRoute, path: '/countries', component: CountriesPage })
const requirementRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/rules/$slug',
  component: function RequirementRoute() {
    const { slug } = requirementRoute.useParams()
    return <RequirementDetailPage slug={slug} />
  },
})

const router = createRouter({
  routeTree: rootRoute.addChildren([legalMapRoute, sourcesRoute, countriesRoute, requirementRoute]),
  defaultPreload: 'intent',
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}

ReactDOM.createRoot(document.getElementById('app')!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
)
