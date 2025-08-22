import { useState, useRef, useEffect } from 'react';
import { MenuIcon, UserIcon, LogOutIcon } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../auth/AuthContext';
interface TopNavbarProps {
  toggleSidebar: () => void;
}
const TopNavbar = ({
  toggleSidebar
}: TopNavbarProps) => {
  const { user, logout } = useAuth();
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsUserMenuOpen(false);
      }
    };

    if (isUserMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isUserMenuOpen]);

  return (
    <header className="bg-white/95 backdrop-blur-sm shadow-lg border-b border-gray-100 z-10 sticky top-0">
      <div className="flex items-center justify-between px-6 py-4">
        {/* Left side - Menu button and breadcrumb */}
        <div className="flex items-center space-x-4">
          <button 
            onClick={toggleSidebar} 
            className="p-2.5 rounded-xl text-gray-500 hover:bg-gray-100 hover:text-gray-700 focus:outline-none transition-all duration-200 md:hidden"
          >
            <MenuIcon size={20} />
          </button>
          
          {/* Current page indicator */}
          <div className="hidden md:flex items-center space-x-2">
            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
            <span className="text-sm font-medium text-gray-600">Admin Dashboard</span>
          </div>
        </div>

        {/* Right side - User menu */}
        <div className="flex items-center space-x-3">
          {/* User Menu */}
          <div className="relative" ref={dropdownRef}>
            <button 
              onClick={() => setIsUserMenuOpen(!isUserMenuOpen)} 
              className="flex items-center space-x-3 p-2 rounded-xl hover:bg-gray-100 focus:outline-none transition-all duration-200"
            >
              <div className="relative">
                {user?.avatar ? (
                  <img 
                    src={user.avatar} 
                    alt={user.name} 
                    className="h-9 w-9 rounded-xl object-cover border-2 border-gray-200" 
                  />
                ) : (
                  <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center">
                    <UserIcon size={18} className="text-white" />
                  </div>
                )}
                <div className="absolute -bottom-1 -right-1 w-3 h-3 bg-green-400 rounded-full border-2 border-white"></div>
              </div>
              <div className="hidden md:block text-left">
                <p className="text-sm font-semibold text-gray-700">
                  {user?.name || 'User'}
                </p>
                <p className="text-xs text-gray-500">{user?.role || 'Staff'}</p>
              </div>
            </button>

            {/* User Dropdown */}
            <AnimatePresence>
              {isUserMenuOpen && (
                <motion.div
                  initial={{ opacity: 0, y: 10, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: 10, scale: 0.95 }}
                  transition={{ duration: 0.2 }}
                  className="absolute right-0 mt-2 w-56 bg-white rounded-2xl shadow-xl border border-gray-100 py-2 z-50"
                >
                  <div className="px-4 py-3 border-b border-gray-100">
                    <p className="text-sm font-semibold text-gray-900">{user?.name || 'User'}</p>
                    <p className="text-xs text-gray-500">{user?.email || `${user?.username || 'user'}@ecoclean.lk`}</p>
                    <p className="text-xs text-green-600 font-medium">{user?.role || 'Staff'}</p>
                  </div>
                  
                  <button 
                    className="flex items-center w-full px-4 py-3 text-sm text-red-600 hover:bg-red-50 transition-colors" 
                    onClick={() => logout()}
                  >
                    <LogOutIcon size={16} className="mr-3 text-red-500" />
                    Sign out
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </header>
  );
};
export default TopNavbar;