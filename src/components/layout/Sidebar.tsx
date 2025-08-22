import { Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { LayoutDashboardIcon, TruckIcon, ClipboardCheckIcon, PackageIcon, UsersIcon, UserIcon, MessageSquareIcon, BellIcon, XIcon, UserCogIcon, LogOutIcon } from 'lucide-react';
import { useAuth } from '../auth/AuthContext';
import { useState } from 'react';
interface SidebarProps {
  isOpen: boolean;
  toggleSidebar: () => void;
}
const Sidebar = ({
  isOpen,
  toggleSidebar
}: SidebarProps) => {
  const location = useLocation();
  const { user, hasAccess, logout } = useAuth();
  
  // You can fetch real counts here when API endpoints are available
  const [counts] = useState({
    pickupRequests: 0,
    serviceRequests: 0,
    inquiries: 0,
    notifications: 0
  });
  
  // TODO: Uncomment and modify when you have real API endpoints
  // useEffect(() => {
  //   const fetchCounts = async () => {
  //     try {
  //       const token = localStorage.getItem('authToken');
  //       // Example API calls:
  //       // const pickupRes = await axios.get('/api/pickup-requests/count', { headers: { Authorization: `Bearer ${token}` }});
  //       // const serviceRes = await axios.get('/api/service-requests/count', { headers: { Authorization: `Bearer ${token}` }});
  //       // setCounts({
  //       //   pickupRequests: pickupRes.data.count,
  //       //   serviceRequests: serviceRes.data.count,
  //       //   inquiries: inquiryRes.data.count,
  //       //   notifications: notificationRes.data.count
  //       // });
  //     } catch (error) {
  //       console.error('Failed to fetch counts:', error);
  //     }
  //   };
  //   fetchCounts();
  // }, []);
  
  const sidebarItems = [{
    name: 'Dashboard',
    path: '/dashboard',
    icon: <LayoutDashboardIcon size={20} />,
    badge: null,
    requiredRole: 'dashboard'
  }, {
    name: 'Pickup Requests',
    path: '/pickup-requests',
    icon: <TruckIcon size={20} />,
    badge: counts.pickupRequests > 0 ? counts.pickupRequests.toString() : null,
    requiredRole: 'pickup-requests'
  }, {
    name: 'Service Requests',
    path: '/service-requests',
    icon: <ClipboardCheckIcon size={20} />,
    badge: counts.serviceRequests > 0 ? counts.serviceRequests.toString() : null,
    requiredRole: 'service-requests'
  }, {
    name: 'Services',
    path: '/services',
    icon: <PackageIcon size={20} />,
    badge: null,
    requiredRole: 'services'
  }, {
    name: 'Staff',
    path: '/staff',
    icon: <UsersIcon size={20} />,
    badge: null,
    requiredRole: 'staff'
  }, {
    name: 'Users',
    path: '/users',
    icon: <UserIcon size={20} />,
    badge: null,
    requiredRole: 'users'
  }, {
    name: 'Inquiries',
    path: '/inquiries',
    icon: <MessageSquareIcon size={20} />,
    badge: counts.inquiries > 0 ? counts.inquiries.toString() : null,
    requiredRole: 'inquiries'
  }, {
    name: 'Notifications',
    path: '/notifications',
    icon: <BellIcon size={20} />,
    badge: counts.notifications > 0 ? counts.notifications.toString() : null,
    requiredRole: 'notifications'
  }, {
    name: 'Employees',
    path: '/employees',
    icon: <UserCogIcon size={20} />,
    badge: null,
    requiredRole: 'employees'
  }];

  // Add Blog management page to sidebar
  sidebarItems.push({
    name: 'Blogs',
    path: '/blogs',
    icon: <ClipboardCheckIcon size={20} />, // You can use a different icon if preferred
    badge: null,
    requiredRole: 'blogs'
  });

  // Filter sidebar items based on user role
  const filteredSidebarItems = sidebarItems.filter(item => hasAccess(item.requiredRole));
  const sidebarVariants = {
    open: {
      width: '280px',
      transition: {
        duration: 0.3,
        ease: "easeInOut"
      }
    },
    closed: {
      width: '0px',
      transition: {
        duration: 0.3,
        ease: "easeInOut"
      }
    }
  };
  return <>
      {/* Mobile overlay */}
      {isOpen && <div className="fixed inset-0 bg-black bg-opacity-60 z-20 md:hidden backdrop-blur-sm" onClick={toggleSidebar} />}
      
      <motion.aside 
        initial={false} 
        animate={isOpen ? 'open' : 'closed'} 
        variants={sidebarVariants} 
        className={`fixed md:relative z-30 h-full overflow-hidden bg-gradient-to-b from-slate-900 via-slate-800 to-slate-900 shadow-2xl border-r border-slate-700`}
      >
        <div className="flex flex-col h-full w-70">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-slate-700/50 bg-gradient-to-r from-green-600/10 to-emerald-600/10">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center shadow-lg">
                <span className="text-white font-bold text-xl">E</span>
              </div>
              <div>
                <h1 className="font-bold text-xl text-white">EcoClean</h1>
                <p className="text-xs text-slate-400">Admin Panel</p>
              </div>
            </div>
            <button 
              onClick={toggleSidebar} 
              className="md:hidden p-2 rounded-lg hover:bg-slate-700/50 text-slate-400 hover:text-white transition-all duration-200"
            >
              <XIcon size={20} />
            </button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 py-6 px-4" style={{ 
            overflowY: 'auto',
            msOverflowStyle: 'none',
            scrollbarWidth: 'none'
          }}>
            <style dangerouslySetInnerHTML={{
              __html: `
                nav::-webkit-scrollbar {
                  display: none;
                }
              `
            }} />
            <div className="space-y-2">
              {filteredSidebarItems.map((item, index) => {
                const isActive = location.pathname === item.path;
                return (
                  <motion.div
                    key={item.path}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.05 }}
                  >
                    <Link 
                      to={item.path} 
                      className={`group relative flex items-center justify-between px-4 py-3.5 rounded-xl transition-all duration-200 ${
                        isActive 
                          ? 'bg-gradient-to-r from-green-500 to-emerald-600 text-white shadow-lg transform scale-[1.02]' 
                          : 'text-slate-300 hover:bg-slate-700/50 hover:text-white hover:translate-x-1'
                      }`}
                    >
                      <div className="flex items-center space-x-3">
                        <span className={`transition-colors ${isActive ? 'text-white' : 'text-slate-400 group-hover:text-green-400'}`}>
                          {item.icon}
                        </span>
                        <span className="font-medium">{item.name}</span>
                      </div>
                      
                      {item.badge && (
                        <span className={`px-2 py-1 text-xs font-bold rounded-full ${
                          isActive 
                            ? 'bg-white/20 text-white' 
                            : 'bg-green-500 text-white'
                        }`}>
                          {item.badge}
                        </span>
                      )}
                      
                      {isActive && (
                        <motion.div
                          layoutId="activeTab"
                          className="absolute left-0 top-0 bottom-0 w-1 bg-white rounded-r-full"
                          initial={false}
                          transition={{ type: "spring", stiffness: 300, damping: 30 }}
                        />
                      )}
                    </Link>
                  </motion.div>
                );
              })}
            </div>
          </nav>

          {/* User Profile */}
          <div className="p-4 border-t border-slate-700/50 bg-gradient-to-r from-slate-800/50 to-slate-900/50">
            <div className="flex items-center space-x-3 p-3 rounded-xl bg-slate-800/50 backdrop-blur-sm">
              <div className="relative">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center shadow-lg">
                  {user?.avatar ? (
                    <img 
                      src={user.avatar} 
                      alt={user.name || user.username} 
                      className="w-full h-full rounded-xl object-cover"
                    />
                  ) : (
                    <UserIcon size={20} className="text-white" />
                  )}
                </div>
                <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-green-400 rounded-full border-2 border-slate-800"></div>
              </div>
              
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-white truncate">
                  {user?.name || user?.username || 'User'}
                </p>
                <p className="text-xs text-slate-400 truncate">
                  {user?.email || (user?.username ? `${user.username}@ecoclean.lk` : 'user@ecoclean.lk')}
                </p>
                <p className="text-xs text-green-400 font-medium truncate">
                  {user?.role || 'Staff'}
                </p>
              </div>
              
              <div className="flex items-center space-x-1">
                <button 
                  className="p-2 rounded-lg hover:bg-red-500/20 text-slate-400 hover:text-red-400 transition-all duration-200"
                  onClick={() => {
                    logout();
                  }}
                  aria-label="Logout"
                >
                  <LogOutIcon size={16} />
                </button>
              </div>
            </div>
          </div>
        </div>
      </motion.aside>
    </>;
};
export default Sidebar;