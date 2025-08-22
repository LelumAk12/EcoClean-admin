import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Toaster } from 'react-hot-toast';
// Auth Provider
import { AuthProvider, useAuth } from './components/auth/AuthContext';
import LoginPage from './components/auth/LoginPage';
// Layout components
import Sidebar from './components/layout/Sidebar';
import TopNavbar from './components/layout/TopNavbar';
// Pages
import Dashboard from './components/dashboard/Dashboard';
import PickupRequestManager from './components/pages/PickupRequestManager';
import ServiceRequestManager from './components/pages/ServiceRequestManager';
import ServicesManager from './components/pages/ServicesManager';
import StaffManager from './components/pages/StaffManager';
import CustomerManager from './components/pages/CustomerManager';
import InquiryManager from './components/pages/InquiryManager';
import NotificationManager from './components/pages/NotificationManager';
import EmployeeManager from './components/pages/EmployeeManager';
import BlogManager from './components/pages/BlogManager';
// Login redirect component - redirects to dashboard if already authenticated
const LoginRedirect = () => {
  const { isAuthenticated } = useAuth();
  
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }
  
  return <LoginPage />;
};
const ProtectedRoute = ({
  children
}: {
  children: React.ReactNode;
}) => {
  const {
    isAuthenticated
  } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
};

// Role-based protected route component
const RoleProtectedRoute = ({
  children,
  requiredRole
}: {
  children: React.ReactNode;
  requiredRole: string;
}) => {
  const { isAuthenticated, hasAccess } = useAuth();
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  
  if (!hasAccess(requiredRole)) {
    return <Navigate to="/dashboard" replace />;
  }
  
  return <>{children}</>;
};
// Admin Layout component
const AdminLayout = ({
  children
}: {
  children: React.ReactNode;
}) => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };
  return <div className="flex h-screen bg-gray-50">
      <Sidebar isOpen={sidebarOpen} toggleSidebar={toggleSidebar} />
      <div className="flex flex-col flex-1 overflow-hidden">
        <TopNavbar toggleSidebar={toggleSidebar} />
        <main className="flex-1 overflow-y-auto p-4 md:p-6 bg-gray-50">
          <AnimatePresence mode="wait">{children}</AnimatePresence>
        </main>
      </div>
    </div>;
};
export function App() {
  return <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<LoginRedirect />} />
          <Route path="/" element={<ProtectedRoute>
                <Navigate to="/dashboard" replace />
              </ProtectedRoute>} />
          <Route path="/dashboard" element={<ProtectedRoute>
                <AdminLayout>
                  <motion.div initial={{
              opacity: 0,
              y: 20
            }} animate={{
              opacity: 1,
              y: 0
            }} exit={{
              opacity: 0,
              y: -20
            }} transition={{
              duration: 0.2
            }}>
                    <Dashboard />
                  </motion.div>
                </AdminLayout>
              </ProtectedRoute>} />
          <Route path="/pickup-requests" element={<ProtectedRoute>
                <AdminLayout>
                  <motion.div initial={{
              opacity: 0,
              y: 20
            }} animate={{
              opacity: 1,
              y: 0
            }} exit={{
              opacity: 0,
              y: -20
            }} transition={{
              duration: 0.2
            }}>
                    <PickupRequestManager />
                  </motion.div>
                </AdminLayout>
              </ProtectedRoute>} />
          <Route path="/service-requests" element={<ProtectedRoute>
                <AdminLayout>
                  <ServiceRequestManager />
                </AdminLayout>
              </ProtectedRoute>} />
          <Route path="/services" element={<RoleProtectedRoute requiredRole="services">
                <AdminLayout>
                  <ServicesManager />
                </AdminLayout>
              </RoleProtectedRoute>} />
          <Route path="/staff" element={<RoleProtectedRoute requiredRole="staff">
                <AdminLayout>
                  <StaffManager />
                </AdminLayout>
              </RoleProtectedRoute>} />
          <Route path="/users" element={<ProtectedRoute>
                <AdminLayout>
                  <CustomerManager />
                </AdminLayout>
              </ProtectedRoute>} />
          <Route path="/inquiries" element={<ProtectedRoute>
                <AdminLayout>
                  <InquiryManager />
                </AdminLayout>
              </ProtectedRoute>} />
          <Route path="/notifications" element={<ProtectedRoute>
                <AdminLayout>
                  <NotificationManager />
                </AdminLayout>
              </ProtectedRoute>} />
          <Route path="/employees" element={<ProtectedRoute>
                <AdminLayout>
                  <EmployeeManager />
                </AdminLayout>
              </ProtectedRoute>} />
          <Route path="/blogs" element={<ProtectedRoute>
                <AdminLayout>
                  <BlogManager />
                </AdminLayout>
              </ProtectedRoute>} />
        </Routes>
        <Toaster 
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#363636',
              color: '#fff',
            },
            success: {
              style: {
                background: '#10b981',
              },
            },
            error: {
              style: {
                background: '#ef4444',
              },
            },
          }}
        />
      </Router>
    </AuthProvider>;
}