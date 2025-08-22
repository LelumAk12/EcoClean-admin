/// <reference types="vite/client" />
import { useState, useEffect } from 'react';
import { SearchIcon, TrashIcon, UserIcon, MailIcon, EyeIcon, UserPlusIcon, ShieldIcon, CheckCircleIcon, XCircleIcon, AlertCircleIcon, XIcon, UsersIcon, UserCheckIcon, UserXIcon, ClockIcon } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import Button from '../common/Button';
import Modal from '../common/Modal';
import { pageAnimations } from '../../utils/animations';

// Toast Notification Types
type ToastType = 'success' | 'error' | 'warning' | 'info';

interface Toast {
  id: string;
  type: ToastType;
  title: string;
  message: string;
}

// Toast Component
const ToastNotification = ({ toast, onRemove }: { toast: Toast; onRemove: (id: string) => void }) => {
  const getToastIcon = () => {
    switch (toast.type) {
      case 'success':
        return <CheckCircleIcon size={22} className="text-green-600" />;
      case 'error':
        return <XCircleIcon size={22} className="text-red-600" />;
      case 'warning':
        return <AlertCircleIcon size={22} className="text-yellow-600" />;
      default:
        return <AlertCircleIcon size={22} className="text-blue-600" />;
    }
  };

  const getToastColors = () => {
    switch (toast.type) {
      case 'success':
        return 'bg-green-50 border-green-200 text-green-900 shadow-green-100';
      case 'error':
        return 'bg-red-50 border-red-200 text-red-900 shadow-red-100';
      case 'warning':
        return 'bg-yellow-50 border-yellow-200 text-yellow-900 shadow-yellow-100';
      default:
        return 'bg-blue-50 border-blue-200 text-blue-900 shadow-blue-100';
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      onRemove(toast.id);
    }, 6000);

    return () => clearTimeout(timer);
  }, [toast.id, onRemove]);

  return (
    <motion.div
      initial={{ opacity: 0, x: 300, scale: 0.8 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 300, scale: 0.8 }}
      transition={{ duration: 0.3, ease: "easeOut" }}
      className={`min-w-[320px] max-w-md w-full ${getToastColors()} border rounded-xl shadow-xl p-4 mb-2 backdrop-blur-sm`}
    >
      <div className="flex items-start">
        <div className="flex-shrink-0 mt-0.5">
          {getToastIcon()}
        </div>
        <div className="ml-3 w-0 flex-1 pt-0.5">
          <p className="text-sm font-bold">{toast.title}</p>
          <p className="text-sm mt-1 opacity-90 leading-relaxed">{toast.message}</p>
        </div>
        <div className="ml-4 flex-shrink-0 flex">
          <button
            className="inline-flex rounded-md p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-gray-300 transition-all duration-200"
            onClick={() => onRemove(toast.id)}
          >
            <span className="sr-only">Dismiss</span>
            <XIcon size={16} />
          </button>
        </div>
      </div>
      
      <motion.div
        className="mt-3 h-1 bg-black bg-opacity-10 rounded-full overflow-hidden"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5 }}
      >
        <motion.div
          className="h-full bg-current opacity-30 rounded-full"
          initial={{ width: "100%" }}
          animate={{ width: "0%" }}
          transition={{ duration: 6, ease: "linear" }}
        />
      </motion.div>
    </motion.div>
  );
};

// Toast Container Component
const ToastContainer = ({ toasts, onRemove }: { toasts: Toast[]; onRemove: (id: string) => void }) => {
  return (
    <div className="fixed top-4 right-4 z-[9999] space-y-2">
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <ToastNotification key={toast.id} toast={toast} onRemove={onRemove} />
        ))}
      </AnimatePresence>
    </div>
  );
};

interface Customer {
  id: number;
  name: string;
  email: string;
  imageURL?: string;
  role: 'admin' | 'user' | 'staff';
  status: 'Active' | 'Inactive' | 'Pending';
}

// Customer Card Component
const CustomerCard = ({ customer, index, onView, onDelete }: { 
  customer: Customer; 
  index: number; 
  onView: () => void; 
  onDelete: () => void; 
}) => {
  const getRoleIcon = () => {
    switch (customer.role) {
      case 'admin':
        return <ShieldIcon size={16} className="text-purple-600" />;
      case 'staff':
        return <UserIcon size={16} className="text-blue-600" />;
      default:
        return <UserIcon size={16} className="text-green-600" />;
    }
  };

  const getRoleColor = () => {
    switch (customer.role) {
      case 'admin':
        return 'bg-purple-100 text-purple-800 border-purple-200';
      case 'staff':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      default:
        return 'bg-green-100 text-green-800 border-green-200';
    }
  };

  const getStatusColor = () => {
    switch (customer.status) {
      case 'Active':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'Inactive':
        return 'bg-red-100 text-red-800 border-red-200';
      default:
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1 }}
      className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden hover:shadow-xl transition-all duration-300 group"
    >
      <div className="p-6">
        <div className="flex items-center space-x-4 mb-4">
          <div className="relative">
            <div className="h-12 w-12 rounded-full overflow-hidden bg-gradient-to-br from-gray-100 to-gray-200">
              {customer.imageURL ? (
                <img 
                  className="h-full w-full object-cover" 
                  src={customer.imageURL} 
                  alt={customer.name}
                  onError={(e) => {
                    e.currentTarget.style.display = 'none';
                    e.currentTarget.nextElementSibling?.classList.remove('hidden');
                  }}
                />
              ) : null}
              <div className={`h-full w-full flex items-center justify-center ${customer.imageURL ? 'hidden' : ''}`}>
                <UserIcon size={24} className="text-gray-500" />
              </div>
            </div>
            <div className={`absolute -bottom-1 -right-1 h-4 w-4 rounded-full border-2 border-white ${customer.status === 'Active' ? 'bg-green-500' : customer.status === 'Inactive' ? 'bg-red-500' : 'bg-yellow-500'}`}></div>
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-lg font-semibold text-gray-900 truncate group-hover:text-emerald-600 transition-colors duration-200">
              {customer.name}
            </h3>
            <p className="text-sm text-gray-500 truncate flex items-center">
              <MailIcon size={14} className="mr-1" />
              {customer.email}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap gap-2 mb-4">
          <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getRoleColor()}`}>
            {getRoleIcon()}
            <span className="ml-1 capitalize">{customer.role === 'user' ? 'Customer' : customer.role}</span>
          </span>
          <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getStatusColor()}`}>
            {customer.status}
          </span>
        </div>

        <div className="flex space-x-2">
          <Button
            variant="outline"
            size="sm"
            icon={<EyeIcon size={16} />}
            onClick={onView}
            className="flex-1 hover:bg-emerald-50 hover:border-emerald-200 hover:text-emerald-700 transition-all duration-200"
          >
            View
          </Button>
          <Button
            variant="danger"
            size="sm"
            icon={<TrashIcon size={16} />}
            onClick={onDelete}
            className="bg-red-50 text-red-600 border-red-200 hover:bg-red-100 hover:border-red-300 transition-all duration-200"
          >
            Delete
          </Button>
        </div>
      </div>
    </motion.div>
  );
};

const CustomerManager = () => {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [selectedCustomer, setSelectedCustomer] = useState<Customer | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [loading, setLoading] = useState(true);
  const [toasts, setToasts] = useState<Toast[]>([]);

  // Toast helper functions
  const addToast = (type: ToastType, title: string, message: string) => {
    const newToast: Toast = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type,
      title,
      message,
    };
    setToasts(prev => [...prev, newToast]);
  };

  const removeToast = (id: string) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  };

  const API_URL = import.meta.env.VITE_API_BASE_URL;
  const fetchCustomers = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('authToken');
      const res = await fetch(`${API_URL}/api/personnel/getAllCustomers`, {
        headers: {
          Authorization: token ? `Bearer ${token}` : '',
        },
      });
      if (!res.ok) throw new Error('Failed to fetch customers');
      const data = await res.json();
      const mapped = (data.users || []).map((user: any) => ({
        id: user._id,
        name: user.name,
        email: user.email,
        imageURL: user.imageUrl,
        role: user.role ? user.role.toLowerCase() : 'user',
        status: 'Active', // Default, since not provided by backend
      }));
      setCustomers(mapped);
    } catch (err) {
      setCustomers([]);
      addToast('error', 'Failed to Load Customers', 'Unable to fetch customer data from the server.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCustomers();
  }, []);
  const filteredCustomers = customers.filter(customer => 
    (statusFilter === 'all' || customer.status === statusFilter) && 
    (customer.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
     customer.email.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 p-6">
      {/* Toast Container */}
      <ToastContainer toasts={toasts} onRemove={removeToast} />
      
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Header Section */}
        <motion.div 
          {...pageAnimations.header}
          className="bg-white rounded-2xl shadow-lg border border-gray-100 p-8"
        >
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between space-y-4 lg:space-y-0">
            <div className="flex items-center space-x-4">
              <div className="bg-gradient-to-r from-emerald-500 to-teal-600 p-3 rounded-xl">
                <UsersIcon size={28} className="text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-emerald-900 to-teal-900 bg-clip-text text-transparent">
                  Customer Management
                </h1>
                <p className="text-gray-500 mt-1">Manage your customer base and user accounts</p>
              </div>
            </div>
            <div className="flex flex-col sm:flex-row gap-3 w-full lg:w-auto">
              <Button 
                variant="primary" 
                icon={<UserPlusIcon size={18} />} 
                onClick={() => setIsAddModalOpen(true)}
                className="bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700 shadow-lg hover:shadow-xl transition-all duration-200"
              >
                Add Customer
              </Button>
            </div>
          </div>
        </motion.div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <motion.div 
            {...pageAnimations.statsCard(0)}
            className="relative bg-gradient-to-br from-emerald-50 via-white to-emerald-100 rounded-2xl shadow-lg border border-emerald-100 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/5 via-transparent to-teal-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-emerald-500 to-teal-600 p-3 rounded-xl shadow-lg">
                  <UsersIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-emerald-600 bg-emerald-100 px-2 py-1 rounded-full">
                    Total
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Total Customers</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-emerald-600 to-teal-600 bg-clip-text text-transparent">
                  {customers.length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-emerald-500 to-teal-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((customers.length / Math.max(customers.length, 10)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>
          
          <motion.div 
            {...pageAnimations.statsCard(1)}
            className="relative bg-gradient-to-br from-green-50 via-white to-green-100 rounded-2xl shadow-lg border border-green-100 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-green-500/5 via-transparent to-emerald-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-green-500 to-emerald-600 p-3 rounded-xl shadow-lg">
                  <UserCheckIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-green-600 bg-green-100 px-2 py-1 rounded-full">
                    Active
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Active</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-green-600 to-emerald-600 bg-clip-text text-transparent">
                  {customers.filter(c => c.status === 'Active').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-green-500 to-emerald-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((customers.filter(c => c.status === 'Active').length / Math.max(customers.length, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>

          <motion.div 
            {...pageAnimations.statsCard(2)}
            className="relative bg-gradient-to-br from-red-50 via-white to-red-100 rounded-2xl shadow-lg border border-red-100 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 via-transparent to-pink-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-red-500 to-pink-600 p-3 rounded-xl shadow-lg">
                  <UserXIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-red-600 bg-red-100 px-2 py-1 rounded-full">
                    Inactive
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Inactive</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-red-600 to-pink-600 bg-clip-text text-transparent">
                  {customers.filter(c => c.status === 'Inactive').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-red-500 to-pink-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((customers.filter(c => c.status === 'Inactive').length / Math.max(customers.length, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>

          <motion.div 
            {...pageAnimations.statsCard(3)}
            className="relative bg-gradient-to-br from-yellow-50 via-white to-yellow-100 rounded-2xl shadow-lg border border-yellow-100 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-yellow-500/5 via-transparent to-orange-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-yellow-500 to-orange-600 p-3 rounded-xl shadow-lg">
                  <ClockIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-yellow-600 bg-yellow-100 px-2 py-1 rounded-full">
                    Pending
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Pending</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-yellow-600 to-orange-600 bg-clip-text text-transparent">
                  {customers.filter(c => c.status === 'Pending').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-yellow-500 to-orange-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((customers.filter(c => c.status === 'Pending').length / Math.max(customers.length, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Main Content Card with Integrated Search/Filter */}
        <div className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden">
          {/* Enhanced Search and Filter Section */}
          <div className="p-6 border-b border-gray-200 bg-gradient-to-r from-gray-50 to-white">
            <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center space-y-4 lg:space-y-0">
              <div className="flex-1 max-w-md">
                <div className="relative">
                  <SearchIcon size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                  <input 
                    type="text" 
                    placeholder="Search customers by name or email..." 
                    className="w-full pl-10 pr-4 py-3 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent bg-white shadow-sm hover:border-gray-300 transition-colors duration-200" 
                    value={searchTerm} 
                    onChange={e => setSearchTerm(e.target.value)} 
                  />
                </div>
              </div>
              <div className="flex flex-wrap gap-3">
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-600 font-medium">Filter by Status:</span>
                  <select 
                    value={statusFilter} 
                    onChange={e => setStatusFilter(e.target.value)} 
                    className="admin-dropdown admin-dropdown-success"
                  >
                    <option value="all">All Statuses</option>
                    <option value="Active">Active</option>
                    <option value="Inactive">Inactive</option>
                    <option value="Pending">Pending</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          {/* Customers Grid */}
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {loading ? (
            // Loading skeleton
            Array.from({ length: 6 }).map((_, index) => (
              <div key={index} className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden animate-pulse">
                <div className="p-6">
                  <div className="flex items-center space-x-4 mb-4">
                    <div className="h-12 w-12 bg-gray-200 rounded-full"></div>
                    <div className="flex-1">
                      <div className="h-4 bg-gray-200 rounded mb-2"></div>
                      <div className="h-3 bg-gray-200 rounded w-3/4"></div>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="h-3 bg-gray-200 rounded"></div>
                    <div className="h-8 bg-gray-200 rounded"></div>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <>
              {filteredCustomers.map((customer, index) => (
                <CustomerCard 
                  key={customer.id} 
                  customer={customer} 
                  index={index}
                  onView={() => {
                    setSelectedCustomer(customer);
                    setIsViewModalOpen(true);
                  }}
                  onDelete={() => {
                    setSelectedCustomer(customer);
                    setIsDeleteModalOpen(true);
                  }}
                />
              ))}
              {filteredCustomers.length === 0 && (
                <div className="col-span-3 py-16 text-center">
                  <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-12">
                    <UsersIcon size={64} className="mx-auto mb-6 text-gray-300" />
                    <h3 className="text-xl font-semibold text-gray-600 mb-2">
                      No customers found
                    </h3>
                    <p className="text-gray-500">
                      No customers match your current filter criteria. Try adjusting your filters or add a new customer.
                    </p>
                  </div>
                </div>
              )}
            </>
          )}
            </div>
          </div>
        </div>
      </div>

      {/* View Customer Modal */}
      <Modal isOpen={isViewModalOpen} onClose={() => setIsViewModalOpen(false)} title="Customer Details" size="lg">
        {selectedCustomer && (
          <div className="space-y-8">
            <div className="flex flex-col sm:flex-row items-center sm:items-start space-y-6 sm:space-y-0 sm:space-x-8">
              <div className="relative">
                <div className="h-32 w-32 rounded-2xl overflow-hidden bg-gradient-to-br from-gray-100 to-gray-200 shadow-lg">
                  {selectedCustomer.imageURL ? (
                    <img 
                      className="h-full w-full object-cover" 
                      src={selectedCustomer.imageURL} 
                      alt={selectedCustomer.name}
                      onError={(e) => {
                        e.currentTarget.style.display = 'none';
                        e.currentTarget.nextElementSibling?.classList.remove('hidden');
                      }}
                    />
                  ) : null}
                  <div className={`h-full w-full flex items-center justify-center ${selectedCustomer.imageURL ? 'hidden' : ''}`}>
                    <UserIcon size={48} className="text-gray-500" />
                  </div>
                </div>
                <div className={`absolute -bottom-2 -right-2 h-8 w-8 rounded-full border-4 border-white shadow-lg ${selectedCustomer.status === 'Active' ? 'bg-green-500' : selectedCustomer.status === 'Inactive' ? 'bg-red-500' : 'bg-yellow-500'}`}></div>
              </div>
              <div className="text-center sm:text-left flex-1">
                <h3 className="text-2xl font-bold text-gray-900 mb-2">
                  {selectedCustomer.name}
                </h3>
                <p className="text-gray-600 mb-4 flex items-center justify-center sm:justify-start">
                  <MailIcon size={18} className="mr-2" />
                  {selectedCustomer.email}
                </p>
                <div className="flex flex-wrap justify-center sm:justify-start gap-3">
                  <span className={`inline-flex items-center px-4 py-2 rounded-full text-sm font-semibold border-2 ${selectedCustomer.role === 'admin' ? 'bg-purple-100 text-purple-800 border-purple-200' : selectedCustomer.role === 'staff' ? 'bg-blue-100 text-blue-800 border-blue-200' : 'bg-green-100 text-green-800 border-green-200'}`}>
                    {selectedCustomer.role === 'admin' ? (
                      <ShieldIcon size={16} className="mr-2" />
                    ) : (
                      <UserIcon size={16} className="mr-2" />
                    )}
                    {selectedCustomer.role === 'admin' ? 'Administrator' : selectedCustomer.role === 'staff' ? 'Staff Member' : 'Customer'}
                  </span>
                  <span className={`inline-flex items-center px-4 py-2 rounded-full text-sm font-semibold border-2 ${selectedCustomer.status === 'Active' ? 'bg-green-100 text-green-800 border-green-200' : selectedCustomer.status === 'Inactive' ? 'bg-red-100 text-red-800 border-red-200' : 'bg-yellow-100 text-yellow-800 border-yellow-200'}`}>
                    {selectedCustomer.status === 'Active' ? (
                      <UserCheckIcon size={16} className="mr-2" />
                    ) : selectedCustomer.status === 'Inactive' ? (
                      <UserXIcon size={16} className="mr-2" />
                    ) : (
                      <ClockIcon size={16} className="mr-2" />
                    )}
                    {selectedCustomer.status}
                  </span>
                </div>
              </div>
            </div>

            <div className="bg-gray-50 rounded-xl p-6">
              <h4 className="text-lg font-semibold text-gray-900 mb-4">Account Information</h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-500 mb-1">Account Type</label>
                  <p className="text-gray-900 capitalize bg-white px-3 py-2 rounded-lg border">{selectedCustomer.role === 'user' ? 'Customer Account' : `${selectedCustomer.role} Account`}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-500 mb-1">Status</label>
                  <p className="text-gray-900 bg-white px-3 py-2 rounded-lg border">{selectedCustomer.status}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-500 mb-1">Email Verified</label>
                  <p className="text-gray-900 bg-white px-3 py-2 rounded-lg border">
                    {selectedCustomer.status === 'Active' ? 'Verified' : 'Pending Verification'}
                  </p>
                </div>
              </div>
            </div>

            <div className="flex justify-end space-x-3 pt-6 border-t border-gray-200">
              <Button 
                variant="outline" 
                onClick={() => setIsViewModalOpen(false)}
                className="hover:bg-gray-50 transition-colors duration-200"
              >
                Close
              </Button>
            </div>
          </div>
        )}
      </Modal>
      {/* Add Customer Modal */}
      <Modal isOpen={isAddModalOpen} onClose={() => setIsAddModalOpen(false)} title="Add New Customer" size="lg">
        <form 
          className="space-y-6"
          onSubmit={async (e) => {
            e.preventDefault();
            const formData = new FormData(e.currentTarget);
            const customerData = {
              name: formData.get('name'),
              email: formData.get('email'),
              imageUrl: formData.get('imageURL'),
              role: formData.get('role'),
              status: formData.get('status'),
            };

            try {
              const token = localStorage.getItem('authToken');
              const res = await fetch(`${API_URL}/api/personnel/addCustomer`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  Authorization: token ? `Bearer ${token}` : '',
                },
                body: JSON.stringify(customerData),
              });

              if (!res.ok) throw new Error('Failed to add customer');

              setIsAddModalOpen(false);
              addToast('success', 'Customer Added', `${customerData.name} has been successfully added to the system.`);
              
              // Refresh the customer list
              await fetchCustomers();
              
              // Reset form
              e.currentTarget.reset();
            } catch (err) {
              addToast('error', 'Add Failed', 'Unable to add customer. Please check the information and try again.');
            }
          }}
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="md:col-span-2">
              <label htmlFor="name" className="block text-sm font-semibold text-gray-700 mb-2">
                Full Name
              </label>
              <input 
                type="text" 
                id="name" 
                name="name"
                required
                className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent bg-white shadow-sm hover:border-gray-300 transition-colors duration-200" 
                placeholder="Enter customer's full name" 
              />
            </div>
            <div className="md:col-span-2">
              <label htmlFor="email" className="block text-sm font-semibold text-gray-700 mb-2">
                Email Address
              </label>
              <input 
                type="email" 
                id="email" 
                name="email"
                required
                className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent bg-white shadow-sm hover:border-gray-300 transition-colors duration-200" 
                placeholder="Enter email address" 
              />
            </div>
            <div className="md:col-span-2">
              <label htmlFor="imageURL" className="block text-sm font-semibold text-gray-700 mb-2">
                Profile Image URL (Optional)
              </label>
              <input 
                type="url" 
                id="imageURL" 
                name="imageURL"
                className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent bg-white shadow-sm hover:border-gray-300 transition-colors duration-200" 
                placeholder="https://example.com/image.jpg" 
              />
            </div>
            <div>
              <label htmlFor="role" className="block text-sm font-semibold text-gray-700 mb-2">
                User Role
              </label>
              <select 
                id="role" 
                name="role"
                className="admin-dropdown admin-dropdown-success w-full"
              >
                <option value="user">Customer</option>
                <option value="staff">Staff Member</option>
                <option value="admin">Administrator</option>
              </select>
            </div>
            <div>
              <label htmlFor="status" className="block text-sm font-semibold text-gray-700 mb-2">
                Account Status
              </label>
              <select 
                id="status" 
                name="status"
                className="admin-dropdown admin-dropdown-success w-full"
              >
                <option value="Active">Active</option>
                <option value="Inactive">Inactive</option>
                <option value="Pending">Pending Approval</option>
              </select>
            </div>
          </div>
          <div className="flex justify-end space-x-3 pt-6 border-t border-gray-200">
            <Button 
              variant="outline" 
              type="button"
              onClick={() => setIsAddModalOpen(false)}
              className="hover:bg-gray-50 transition-colors duration-200"
            >
              Cancel
            </Button>
            <Button 
              type="submit" 
              variant="primary"
              className="bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700 shadow-lg hover:shadow-xl transition-all duration-200"
            >
              Add Customer
            </Button>
          </div>
        </form>
      </Modal>
      {/* Delete Confirmation Modal */}
      <Modal isOpen={isDeleteModalOpen} onClose={() => setIsDeleteModalOpen(false)} title="Delete Customer">
        {selectedCustomer && (
          <div className="space-y-6">
            <div className="flex items-start space-x-4">
              <div className="flex-shrink-0">
                <div className="h-12 w-12 rounded-full bg-red-100 flex items-center justify-center">
                  <TrashIcon size={24} className="text-red-600" />
                </div>
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                  Confirm Customer Deletion
                </h3>
                <p className="text-gray-600 leading-relaxed">
                  Are you sure you want to delete{' '}
                  <span className="font-semibold text-gray-900">{selectedCustomer.name}</span>? 
                  This action cannot be undone and will permanently remove:
                </p>
                <ul className="mt-3 text-sm text-gray-600 space-y-1">
                  <li className="flex items-center">
                    <span className="w-1.5 h-1.5 bg-red-500 rounded-full mr-2"></span>
                    Customer profile and account information
                  </li>
                  <li className="flex items-center">
                    <span className="w-1.5 h-1.5 bg-red-500 rounded-full mr-2"></span>
                    Associated order history and transactions
                  </li>
                  <li className="flex items-center">
                    <span className="w-1.5 h-1.5 bg-red-500 rounded-full mr-2"></span>
                    Communication records and preferences
                  </li>
                </ul>
              </div>
            </div>
            
            <div className="bg-red-50 border border-red-200 rounded-xl p-4">
              <div className="flex items-center">
                <AlertCircleIcon size={20} className="text-red-600 mr-2" />
                <p className="text-red-800 text-sm font-medium">
                  This action is permanent and cannot be reversed.
                </p>
              </div>
            </div>

            <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200">
              <Button 
                variant="outline" 
                onClick={() => setIsDeleteModalOpen(false)}
                className="hover:bg-gray-50 transition-colors duration-200"
              >
                Cancel
              </Button>
              <Button 
                variant="danger" 
                onClick={async () => {
                  if (!selectedCustomer) return;
                  try {
                    const token = localStorage.getItem('authToken');
                    const res = await fetch(`${API_URL}/api/personnel/deleteCustomer/${selectedCustomer.id}`, {
                      method: 'DELETE',
                      headers: {
                        Authorization: token ? `Bearer ${token}` : '',
                      },
                    });
                    if (!res.ok) throw new Error('Failed to delete customer');
                    
                    setIsDeleteModalOpen(false);
                    setSelectedCustomer(null);
                    addToast('success', 'Customer Deleted', `${selectedCustomer.name} has been successfully removed from the system.`);
                    
                    // Refresh the customer list
                    await fetchCustomers();
                  } catch (err) {
                    addToast('error', 'Delete Failed', 'Unable to delete customer. Please try again.');
                  }
                }}
                className="bg-red-600 hover:bg-red-700 text-white shadow-lg hover:shadow-xl transition-all duration-200"
              >
                Delete Customer
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default CustomerManager;