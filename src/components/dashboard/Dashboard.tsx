/// <reference types="vite/client" />
import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { TruckIcon, UsersIcon, ClipboardCheckIcon, PackageIcon, CalendarIcon, UserIcon, AlertCircleIcon, 
         TrendingUpIcon, TrendingDownIcon, FilterIcon, ChevronRightIcon, 
         MapPinIcon, PhoneIcon, CheckCircleIcon, ClockIcon, XCircleIcon } from 'lucide-react';
import Table from '../common/Table';
import axios from 'axios';

interface DashboardStats {
  totalPickups: number;
  totalCustomers: number;
  totalEmployees: number;
  totalServices: number;
  pendingPickups: number;
  completedPickups: number;
  totalNotifications: number;
}

interface PickupRequest {
  id: string;
  username: string;
  contact: string;
  location: string;
  date: string;
  status: string;
  service?: string;
}

const Dashboard = () => {
  const [stats, setStats] = useState<DashboardStats>({
    totalPickups: 0,
    totalCustomers: 0,
    totalEmployees: 0,
    totalServices: 0,
    pendingPickups: 0,
    completedPickups: 0,
    totalNotifications: 0
  });

  const [recentPickups, setRecentPickups] = useState<PickupRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Animation variants
  const containerVariants = {
    hidden: {
      opacity: 0
    },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: {
      y: 20,
      opacity: 0
    },
    visible: {
      y: 0,
      opacity: 1
    }
  };

  // Data fetching function
  const fetchDashboardData = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const token = localStorage.getItem('authToken');
      const headers = { Authorization: `Bearer ${token}` };

      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      // Fetch pickup requests
      const pickupResponse = await fetch(`${baseUrl}/api/personnel/get-all-request`, {
        headers
      });
      const pickupData = await pickupResponse.json();

      // Fetch customers
      const customerResponse = await fetch(`${baseUrl}/api/personnel/getAllCustomers`, {
        headers
      });
      const customerData = await customerResponse.json();
      
      // Process customers
      const allCustomers = customerData.users || [];

      // Fetch employees
      const employeeResponse = await axios.get(`${baseUrl}/api/personnel/all-employees`, {
        headers
      });

      // Fetch services
      const serviceResponse = await fetch(`${baseUrl}/api/personnel/get-all-services`, {
        headers
      });
      if (!serviceResponse.ok) throw new Error('Failed to fetch services');
      const serviceData = await serviceResponse.json();
      
      // Process services - based on ServicesManager implementation
      const allServices = serviceData.data || [];
      
      console.log('Full services response:', serviceData);
      console.log('Services data array:', allServices);
      console.log('Services count:', allServices.length);

      // Process pickup requests
      const allPickups = pickupData.success && Array.isArray(pickupData.allPickups) ? pickupData.allPickups : [];
      const pendingPickups = allPickups.filter((p: any) => p.status === 'Pending').length;
      const completedPickups = allPickups.filter((p: any) => p.status === 'Completed').length;

      // Get recent pickups (last 5)
      const recentPickupData: PickupRequest[] = allPickups
        .slice(0, 5)
        .map((req: any) => ({
          id: req._id,
          username: req.userName || 'Unknown',
          contact: req.contact || '',
          location: req.location || 'Not specified',
          date: req.date ? new Date(req.date).toLocaleDateString() : '',
          status: req.status || 'Pending',
          service: req.serviceType || 'General Waste'
        }));

      // Update stats
      setStats({
        totalPickups: allPickups.length,
        totalCustomers: allCustomers.length,
        totalEmployees: employeeResponse.data?.data?.length || 0,
        totalServices: Array.isArray(allServices) ? allServices.length : 0,
        pendingPickups,
        completedPickups,
        totalNotifications: 0
      });

      setRecentPickups(recentPickupData);

    } catch (err: any) {
      console.error('Error fetching dashboard data:', err);
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);
  // Table columns for pickup requests
  const pickupColumns = [{
    header: 'Customer',
    accessor: 'username',
    cell: (value: string) => (
      <div className="flex items-center">
        <UserIcon size={16} className="mr-2 text-gray-400" />
        <span className="font-medium">{value}</span>
      </div>
    )
  }, {
    header: 'Location',
    accessor: 'location'
  }, {
    header: 'Service Type',
    accessor: 'service'
  }, {
    header: 'Date',
    accessor: 'date'
  }, {
    header: 'Status',
    accessor: 'status',
    cell: (value: string) => <span className={`px-2 py-1 text-xs font-medium rounded-full ${value === 'Completed' ? 'bg-green-100 text-green-800' : value === 'Pending' ? 'bg-yellow-100 text-yellow-800' : value === 'Accepted' ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'}`}>
          {value}
        </span>
  }];

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-50 via-blue-50 to-indigo-50 p-6">
        <div className="max-w-7xl mx-auto">
          <div className="bg-white rounded-2xl shadow-xl border border-gray-100 p-8 mb-8">
            <div className="flex items-center justify-between">
              <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-blue-900 to-indigo-900 bg-clip-text text-transparent">
                Dashboard Overview
              </h1>
            </div>
          </div>
          <div className="flex items-center justify-center h-96 bg-white rounded-2xl shadow-lg">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-4 border-blue-500 border-t-transparent mx-auto mb-4"></div>
              <p className="text-gray-600 text-lg font-medium">Loading dashboard...</p>
              <p className="text-gray-400 text-sm mt-1">Please wait while we fetch your data</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-50 via-blue-50 to-indigo-50 p-6">
        <div className="max-w-7xl mx-auto">
          <div className="bg-white rounded-2xl shadow-xl border border-gray-100 p-8 mb-8">
            <div className="flex items-center justify-between">
              <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-blue-900 to-indigo-900 bg-clip-text text-transparent">
                Dashboard Overview
              </h1>
            </div>
          </div>
          <div className="flex items-center justify-center h-96 bg-white rounded-2xl shadow-lg">
            <div className="text-center">
              <div className="p-4 bg-red-100 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                <AlertCircleIcon size={32} className="text-red-500" />
              </div>
              <p className="text-red-600 text-lg font-medium">{error}</p>
              <p className="text-gray-400 text-sm mt-1">Please try refreshing the page</p>
            </div>
          </div>
        </div>
      </div>
    );
  }
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 p-4 lg:p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Enhanced Hero Header with Quick Actions */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white/80 backdrop-blur-sm rounded-3xl shadow-xl border border-gray-100 p-6 lg:p-8"
        >
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span className="text-sm font-medium text-green-600">System Online</span>
              </div>
              <h1 className="text-3xl lg:text-4xl font-bold bg-gradient-to-r from-gray-900 via-blue-900 to-indigo-900 bg-clip-text text-transparent">
                Dashboard Overview
              </h1>
              <p className="text-gray-600 mt-2 text-base lg:text-lg">
                Welcome back! Here's your business insights at a glance.
              </p>
            </div>
            
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex items-center space-x-3 bg-gradient-to-r from-blue-50 to-indigo-50 px-4 py-3 rounded-2xl border border-blue-100">
                <div className="p-2 bg-blue-100 rounded-xl">
                  <CalendarIcon size={18} className="text-blue-600" />
                </div>
                <div>
                  <p className="text-xs text-gray-500 font-medium">Today</p>
                  <p className="text-sm font-semibold text-gray-800">
                    {new Date().toLocaleDateString('en-US', {
                      weekday: 'short',
                      month: 'short',
                      day: 'numeric'
                    })}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Enhanced Stats Cards with better animations */}
        <motion.div 
          variants={containerVariants} 
          initial="hidden" 
          animate="visible" 
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6"
        >
          {/* Total Pickups Card */}
          <motion.div variants={itemVariants}>
            <div className="group bg-white/90 backdrop-blur-sm rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-2xl hover:scale-105 transition-all duration-300 relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-br from-green-50 to-emerald-50 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-3 bg-gradient-to-br from-green-100 to-emerald-100 rounded-2xl group-hover:scale-110 transition-transform duration-300">
                    <TruckIcon size={24} className="text-green-600" />
                  </div>
                  <div className="text-right">
                    <div className="flex items-center gap-1 text-green-600">
                      <TrendingUpIcon size={14} />
                      <span className="text-xs font-medium">+12%</span>
                    </div>
                  </div>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600 mb-1">Total Pickups</p>
                  <p className="text-3xl font-bold text-gray-900 mb-2">{stats.totalPickups}</p>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                      <span className="text-xs text-gray-500">{stats.completedPickups} completed</span>
                    </div>
                    <ChevronRightIcon size={16} className="text-gray-400 group-hover:text-gray-600 transition-colors" />
                  </div>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Total Customers Card */}
          <motion.div variants={itemVariants}>
            <div className="group bg-white/90 backdrop-blur-sm rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-2xl hover:scale-105 transition-all duration-300 relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-br from-blue-50 to-sky-50 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-3 bg-gradient-to-br from-blue-100 to-sky-100 rounded-2xl group-hover:scale-110 transition-transform duration-300">
                    <UsersIcon size={24} className="text-blue-600" />
                  </div>
                  <div className="text-right">
                    <div className="flex items-center gap-1 text-blue-600">
                      <TrendingUpIcon size={14} />
                      <span className="text-xs font-medium">+8%</span>
                    </div>
                  </div>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600 mb-1">Total Customers</p>
                  <p className="text-3xl font-bold text-gray-900 mb-2">{stats.totalCustomers}</p>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                      <span className="text-xs text-gray-500">Active users</span>
                    </div>
                    <ChevronRightIcon size={16} className="text-gray-400 group-hover:text-gray-600 transition-colors" />
                  </div>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Pending Requests Card */}
          <motion.div variants={itemVariants}>
            <div className="group bg-white/90 backdrop-blur-sm rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-2xl hover:scale-105 transition-all duration-300 relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-br from-amber-50 to-orange-50 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-3 bg-gradient-to-br from-amber-100 to-orange-100 rounded-2xl group-hover:scale-110 transition-transform duration-300">
                    <ClockIcon size={24} className="text-amber-600" />
                  </div>
                  <div className="text-right">
                    <div className="flex items-center gap-1 text-amber-600">
                      <TrendingDownIcon size={14} />
                      <span className="text-xs font-medium">-3%</span>
                    </div>
                  </div>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600 mb-1">Pending Requests</p>
                  <p className="text-3xl font-bold text-gray-900 mb-2">{stats.pendingPickups}</p>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-amber-500 rounded-full animate-pulse"></div>
                      <span className="text-xs text-gray-500">Needs attention</span>
                    </div>
                    <ChevronRightIcon size={16} className="text-gray-400 group-hover:text-gray-600 transition-colors" />
                  </div>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Total Services Card */}
          <motion.div variants={itemVariants}>
            <div className="group bg-white/90 backdrop-blur-sm rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-2xl hover:scale-105 transition-all duration-300 relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-br from-indigo-50 to-purple-50 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-3 bg-gradient-to-br from-indigo-100 to-purple-100 rounded-2xl group-hover:scale-110 transition-transform duration-300">
                    <PackageIcon size={24} className="text-indigo-600" />
                  </div>
                  <div className="text-right">
                    <div className="flex items-center gap-1 text-indigo-600">
                      <TrendingUpIcon size={14} />
                      <span className="text-xs font-medium">+5%</span>
                    </div>
                  </div>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600 mb-1">Total Services</p>
                  <p className="text-3xl font-bold text-gray-900 mb-2">{stats.totalServices}</p>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
                      <span className="text-xs text-gray-500">Available options</span>
                    </div>
                    <ChevronRightIcon size={16} className="text-gray-400 group-hover:text-gray-600 transition-colors" />
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        </motion.div>

        {/* Enhanced Main Content with better layout */}
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
          {/* Recent Pickup Requests - Enhanced */}
          <div className="xl:col-span-3">
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="bg-white/90 backdrop-blur-sm rounded-3xl shadow-xl border border-gray-100 overflow-hidden"
            >
              <div className="bg-gradient-to-r from-gray-50 via-blue-50 to-indigo-50 px-6 lg:px-8 py-6 border-b border-gray-100">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                  <div className="flex items-center gap-4">
                    <div className="p-3 bg-blue-100 rounded-2xl">
                      <TruckIcon size={24} className="text-blue-600" />
                    </div>
                    <div>
                      <h3 className="text-xl lg:text-2xl font-bold text-gray-900">Recent Pickup Requests</h3>
                      <p className="text-gray-600 text-sm">Latest customer requests and their status</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button className="flex items-center gap-2 px-3 py-2 bg-white rounded-xl border border-gray-200 hover:bg-gray-50 transition-colors text-sm">
                      <FilterIcon size={16} className="text-gray-500" />
                      Filter
                    </button>
                    <div className="bg-blue-100 text-blue-800 px-3 py-2 rounded-xl text-sm font-medium">
                      {recentPickups.length} requests
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="p-6 lg:p-8">
                {recentPickups.length > 0 ? (
                  <div className="space-y-4">
                    {recentPickups.map((pickup, index) => (
                      <motion.div
                        key={pickup.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.1 }}
                        className="group bg-gradient-to-r from-white to-gray-50 border border-gray-100 rounded-2xl p-4 hover:shadow-lg hover:border-blue-200 transition-all duration-200"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
                          <div className="flex items-center gap-3 flex-1">
                            <div className="w-10 h-10 bg-gradient-to-br from-blue-100 to-indigo-100 rounded-xl flex items-center justify-center">
                              <UserIcon size={18} className="text-blue-600" />
                            </div>
                            <div>
                              <p className="font-semibold text-gray-900">{pickup.username}</p>
                              <div className="flex items-center gap-4 text-sm text-gray-500 mt-1">
                                <div className="flex items-center gap-1">
                                  <MapPinIcon size={14} />
                                  <span>{pickup.location}</span>
                                </div>
                                <div className="flex items-center gap-1">
                                  <PhoneIcon size={14} />
                                  <span>{pickup.contact}</span>
                                </div>
                              </div>
                            </div>
                          </div>
                          
                          <div className="flex items-center gap-4">
                            <div className="text-sm">
                              <p className="text-gray-500 mb-1">Service</p>
                              <p className="font-medium text-gray-900">{pickup.service}</p>
                            </div>
                            <div className="text-sm">
                              <p className="text-gray-500 mb-1">Date</p>
                              <p className="font-medium text-gray-900">{pickup.date}</p>
                            </div>
                            <div>
                              <span className={`inline-flex items-center gap-1 px-3 py-2 text-xs font-medium rounded-xl ${
                                pickup.status === 'Completed' 
                                  ? 'bg-green-100 text-green-800' 
                                  : pickup.status === 'Pending' 
                                  ? 'bg-amber-100 text-amber-800' 
                                  : pickup.status === 'Accepted' 
                                  ? 'bg-blue-100 text-blue-800' 
                                  : 'bg-gray-100 text-gray-800'
                              }`}>
                                {pickup.status === 'Completed' && <CheckCircleIcon size={14} />}
                                {pickup.status === 'Pending' && <ClockIcon size={14} />}
                                {pickup.status === 'Cancelled' && <XCircleIcon size={14} />}
                                {pickup.status}
                              </span>
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-16">
                    <div className="p-4 bg-gray-100 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                      <TruckIcon size={24} className="text-gray-400" />
                    </div>
                    <p className="text-gray-500 text-lg font-medium">No pickup requests found</p>
                    <p className="text-gray-400 text-sm mt-1">New requests will appear here</p>
                  </div>
                )}
              </div>
            </motion.div>
          </div>

          {/* Quick Actions Sidebar */}
          <div className="xl:col-span-1">
            <motion.div 
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.4 }}
              className="bg-white/90 backdrop-blur-sm rounded-3xl shadow-xl border border-gray-100 p-6"
            >
              <h3 className="text-lg font-bold text-gray-900 mb-6">Quick Actions</h3>
              <div className="space-y-3">
                <button className="w-full flex items-center gap-3 p-4 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-2xl hover:from-blue-100 hover:to-indigo-100 transition-all duration-200 text-left group">
                  <div className="p-2 bg-blue-100 rounded-xl group-hover:scale-110 transition-transform">
                    <TruckIcon size={18} className="text-blue-600" />
                  </div>
                  <div>
                    <p className="font-medium text-gray-900">View All Pickups</p>
                    <p className="text-xs text-gray-500">Manage requests</p>
                  </div>
                  <ChevronRightIcon size={16} className="text-gray-400 ml-auto" />
                </button>
                
                <button className="w-full flex items-center gap-3 p-4 bg-gradient-to-r from-green-50 to-emerald-50 rounded-2xl hover:from-green-100 hover:to-emerald-100 transition-all duration-200 text-left group">
                  <div className="p-2 bg-green-100 rounded-xl group-hover:scale-110 transition-transform">
                    <UsersIcon size={18} className="text-green-600" />
                  </div>
                  <div>
                    <p className="font-medium text-gray-900">Manage Customers</p>
                    <p className="text-xs text-gray-500">User accounts</p>
                  </div>
                  <ChevronRightIcon size={16} className="text-gray-400 ml-auto" />
                </button>
                
                <button className="w-full flex items-center gap-3 p-4 bg-gradient-to-r from-purple-50 to-indigo-50 rounded-2xl hover:from-purple-100 hover:to-indigo-100 transition-all duration-200 text-left group">
                  <div className="p-2 bg-purple-100 rounded-xl group-hover:scale-110 transition-transform">
                    <PackageIcon size={18} className="text-purple-600" />
                  </div>
                  <div>
                    <p className="font-medium text-gray-900">Services</p>
                    <p className="text-xs text-gray-500">Manage offerings</p>
                  </div>
                  <ChevronRightIcon size={16} className="text-gray-400 ml-auto" />
                </button>
              </div>
              
              {/* Quick Stats */}
              <div className="mt-8 p-4 bg-gradient-to-br from-gray-50 to-blue-50 rounded-2xl">
                <h4 className="font-medium text-gray-900 mb-3">Today's Summary</h4>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Completed</span>
                    <span className="font-medium text-green-600">{stats.completedPickups}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Pending</span>
                    <span className="font-medium text-amber-600">{stats.pendingPickups}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Total Customers</span>
                    <span className="font-medium text-blue-600">{stats.totalCustomers}</span>
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  );
};
export default Dashboard;