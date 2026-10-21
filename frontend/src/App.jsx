import {
  Navigate,
  Route,
  Routes,
} from 'react-router'

import './App.css'
import './styles/pages/reports.css'
import './styles/pages/settings.css'

import ProtectedRoute from './auth/ProtectedRoute'
import PublicOnlyRoute from './auth/PublicOnlyRoute'
import AppLayout from './components/AppLayout'
import DashboardPage from './pages/dashboard/DashboardPage'
import FindingDetailPage from './pages/findings/FindingDetailPage'
import FindingsPage from './pages/findings/FindingsPage'
import ForgotPasswordPage from './pages/ForgotPasswordPage'
import InvitationPage from './pages/InvitationPage'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import ResetPasswordPage from './pages/ResetPasswordPage'
import ReportsPage from './pages/reports/ReportsPage'
import VerifyEmailPage from './pages/VerifyEmailPage'
import SettingsPage from './pages/settings/SettingsPage'
import ScanDetailPage from './pages/scan-detail/ScanDetailPage'
import NewAssessmentPage from './pages/scans/NewAssessmentPage'
import ScansPage from './pages/scans/ScansPage'
import TargetDetailPage from './pages/targets/TargetDetailPage'
import TargetsPage from './pages/targets/TargetsPage'

export default function App() {
  return (
    <Routes>
      <Route
        path="/"
        element={
          <Navigate
            to="/dashboard"
            replace
          />
        }
      />

      <Route
        path="/invite"
        element={<InvitationPage />}
      />

      <Route
        element={
          <PublicOnlyRoute />
        }
      >
        <Route
          path="/login"
          element={<LoginPage />}
        />

        <Route
          path="/register"
          element={<RegisterPage />}
        />

        <Route
          path="/verify-email"
          element={<VerifyEmailPage />}
        />

        <Route
          path="/forgot-password"
          element={<ForgotPasswordPage />}
        />

        <Route
          path="/reset-password"
          element={<ResetPasswordPage />}
        />
      </Route>

      <Route
        element={
          <ProtectedRoute />
        }
      >
        <Route
          element={<AppLayout />}
        >
          <Route
            path="/dashboard"
            element={
              <DashboardPage />
            }
          />

          <Route
            path="/targets"
            element={
              <TargetsPage />
            }
          />

          <Route
            path="/targets/:targetId"
            element={
              <TargetDetailPage />
            }
          />

          <Route
            path="/findings"
            element={
              <FindingsPage />
            }
          />

          <Route
            path="/findings/:findingId"
            element={
              <FindingDetailPage />
            }
          />

          <Route
            path="/reports"
            element={
              <ReportsPage />
            }
          />

          <Route
            path="/settings"
            element={
              <SettingsPage />
            }
          />

          <Route
            path="/scans"
            element={
              <ScansPage />
            }
          />

          <Route
            path="/scans/new"
            element={
              <NewAssessmentPage />
            }
          />

          <Route
            path="/scans/:scanId"
            element={
              <ScanDetailPage />
            }
          />
        </Route>
      </Route>

      <Route
        path="*"
        element={
          <Navigate
            to="/dashboard"
            replace
          />
        }
      />
    </Routes>
  )
}
