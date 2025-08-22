/// <reference types="vite/client" />
import { useState, useEffect } from 'react';
import { SearchIcon, EditIcon, TrashIcon, UserIcon, PhoneIcon, MailIcon, MapPinIcon, UserPlusIcon, CakeIcon, KeyIcon, EyeIcon, EyeOffIcon, ShieldIcon, CheckCircleIcon, XCircleIcon, AlertCircleIcon, XIcon, UsersIcon } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
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
interface StaffMember {
  id: string;
  name: string;
  gender: string;
  age: number;
  birthday: string;
  nic: string;
  phone: string;
  address: string;
  email: string;
  username: string;
  password: string;
  role: string;
  // Optionally add avatar, etc.
}

const StaffManager = () => {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [selectedStaff, setSelectedStaff] = useState<StaffMember | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [staffMembers, setStaffMembers] = useState<StaffMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
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

  const fetchStaffMembers = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('authToken');
      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      const res = await axios.get(`${baseUrl}/api/personnel/getAllPersonnels`, {
        headers: {
          Authorization: token ? `Bearer ${token}` : undefined,
        },
      });
      
      const mapped = (res.data.users || []).map((person: any) => ({
        id: person._id,
        name: person.fullName,
        gender: person.gender,
        age: person.age,
        birthday: person.birthDay,
        nic: person.nic,
        phone: person.contact,
        address: person.adress,
        email: person.email,
        username: person.userName,
        password: person.password,
        role: person.role,
      }));
      setStaffMembers(mapped);
    } catch (err) {
      addToast('error', 'Failed to Load Personnel', 'Unable to fetch personnel data from the server.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStaffMembers();
  }, []);

  // Filter staff members based on search term
  const filteredStaff = staffMembers.filter(staff => {
    const term = searchTerm.toLowerCase();
    return (
      staff.name.toLowerCase().includes(term) ||
      staff.email.toLowerCase().includes(term) ||
      staff.username.toLowerCase().includes(term) ||
      staff.role.toLowerCase().includes(term) ||
      staff.address.toLowerCase().includes(term) ||
      staff.phone.toLowerCase().includes(term) ||
      staff.nic.toLowerCase().includes(term)
    );
  });

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
              <div className="bg-gradient-to-r from-indigo-500 to-purple-600 p-3 rounded-xl">
                <UsersIcon size={28} className="text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-indigo-900 to-purple-900 bg-clip-text text-transparent">
                  Personnel Management
                </h1>
                <p className="text-gray-500 mt-1">Manage your team members and their access</p>
              </div>
            </div>
            <div className="flex flex-col sm:flex-row gap-3 w-full lg:w-auto">
              <Button 
                variant="primary" 
                icon={<UserPlusIcon size={18} />} 
                onClick={() => setIsAddModalOpen(true)}
                className="bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 shadow-lg hover:shadow-xl transition-all duration-200"
              >
                Add Personnel
              </Button>
            </div>
          </div>
        </motion.div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <motion.div 
            {...pageAnimations.statsCard(0)}
            className="relative bg-gradient-to-br from-indigo-50 via-white to-indigo-100 rounded-2xl shadow-lg border border-indigo-100 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 via-transparent to-purple-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-indigo-500 to-purple-600 p-3 rounded-xl shadow-lg">
                  <UsersIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-indigo-600 bg-indigo-100 px-2 py-1 rounded-full">
                    Personnel
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Total Personnel</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
                  {staffMembers.length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-indigo-500 to-purple-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((staffMembers.length / Math.max(staffMembers.length, 10)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>
          
          <motion.div 
            {...pageAnimations.statsCard(1)}
            className="relative bg-gradient-to-br from-purple-50 via-white to-purple-100 rounded-2xl shadow-lg border border-purple-100 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-purple-500/5 via-transparent to-pink-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-purple-500 to-pink-600 p-3 rounded-xl shadow-lg">
                  <ShieldIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-purple-600 bg-purple-100 px-2 py-1 rounded-full">
                    Admin
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Administrators</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-purple-600 to-pink-600 bg-clip-text text-transparent">
                  {staffMembers.filter(s => s.role === 'Admin').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-purple-500 to-pink-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((staffMembers.filter(s => s.role === 'Admin').length / Math.max(staffMembers.length, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>

          <motion.div 
            {...pageAnimations.statsCard(2)}
            className="relative bg-gradient-to-br from-blue-50 via-white to-blue-100 rounded-2xl shadow-lg border border-blue-100 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-transparent to-cyan-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-blue-500 to-cyan-600 p-3 rounded-xl shadow-lg">
                  <UserIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-blue-600 bg-blue-100 px-2 py-1 rounded-full">
                    Staff
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Staff Members</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-cyan-600 bg-clip-text text-transparent">
                  {staffMembers.filter(s => s.role === 'Staff').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-blue-500 to-cyan-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((staffMembers.filter(s => s.role === 'Staff').length / Math.max(staffMembers.length, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Personnel Table */}
        <motion.div 
          {...pageAnimations.mainContent}
          className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden"
        >
          <div className="p-6 border-b border-gray-200">
            <h2 className="text-xl font-semibold text-gray-800">Personnel Directory</h2>
            <p className="text-gray-500 mt-1">View and manage all personnel information</p>
          </div>
          
          {/* Enhanced Search Section */}
          <div className="p-6 border-b border-gray-200 bg-gradient-to-r from-gray-50 to-white">
            <div className="relative max-w-md">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <SearchIcon className="h-5 w-5 text-gray-400" />
              </div>
              <input
                type="text"
                placeholder="Search personnel by name, email, or role..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-xl leading-5 bg-white placeholder-gray-500 focus:outline-none focus:placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all duration-200 shadow-sm hover:border-gray-400"
              />
            </div>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gradient-to-r from-gray-50 to-gray-100">
                <tr>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Personnel</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Role</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Contact</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Location</th>
                  <th className="px-6 py-4 text-center text-xs font-semibold text-gray-600 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {loading ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center">
                      <div className="flex flex-col items-center">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600 mb-4"></div>
                        <p className="text-gray-500">Loading personnel...</p>
                      </div>
                    </td>
                  </tr>
                ) : filteredStaff.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center">
                      <div className="flex flex-col items-center">
                        <UsersIcon size={48} className="text-gray-300 mb-4" />
                        <h3 className="text-lg font-medium text-gray-600 mb-2">No personnel found</h3>
                        <p className="text-gray-500">No personnel match your search criteria.</p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  filteredStaff.map((staff, index) => (
                    <motion.tr 
                      key={staff.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.05 }}
                      className="hover:bg-gray-50 transition-colors duration-200"
                    >
                      <td className="px-6 py-4">
                        <div className="flex items-center">
                          <div className="h-10 w-10 rounded-full bg-gradient-to-r from-indigo-500 to-purple-600 flex items-center justify-center text-white font-semibold text-sm">
                            {staff.name.charAt(0).toUpperCase()}
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-medium text-gray-900">{staff.name}</div>
                            <div className="text-sm text-gray-500">{staff.username}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex px-3 py-1 text-xs font-semibold rounded-full ${
                          staff.role === 'Admin' 
                            ? 'bg-purple-100 text-purple-800' 
                            : 'bg-blue-100 text-blue-800'
                        }`}>
                          {staff.role}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="text-sm text-gray-900">{staff.email}</div>
                        <div className="text-sm text-gray-500">{staff.phone}</div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="text-sm text-gray-900 max-w-xs truncate">{staff.address}</div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex justify-center space-x-2">
                          <Button 
                            variant="outline" 
                            size="sm" 
                            icon={<EyeIcon size={14} />} 
                            onClick={() => {
                              setSelectedStaff(staff);
                              setIsViewModalOpen(true);
                            }}
                            className="hover:bg-indigo-50 hover:border-indigo-300 hover:text-indigo-600 transition-all duration-200"
                          >
                            View
                          </Button>
                          <Button 
                            variant="outline" 
                            size="sm" 
                            icon={<EditIcon size={14} />} 
                            onClick={() => {
                              setSelectedStaff(staff);
                              setIsEditModalOpen(true);
                            }}
                            className="hover:bg-blue-50 hover:border-blue-300 hover:text-blue-600 transition-all duration-200"
                          >
                            Edit
                          </Button>
                          <Button 
                            variant="danger" 
                            size="sm" 
                            icon={<TrashIcon size={14} />} 
                            onClick={() => {
                              setSelectedStaff(staff);
                              setIsDeleteModalOpen(true);
                            }}
                            className="hover:bg-red-50 hover:border-red-300 transition-all duration-200"
                          >
                            Delete
                          </Button>
                        </div>
                      </td>
                    </motion.tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </motion.div>
      </div>
      {/* View Staff Modal */}
      <Modal isOpen={isViewModalOpen} onClose={() => setIsViewModalOpen(false)} title="Personnel Details" size="lg">
        {selectedStaff && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row items-center sm:items-start space-y-4 sm:space-y-0 sm:space-x-6 p-6 bg-gradient-to-r from-indigo-50 to-purple-50 rounded-xl">
              <div className="h-20 w-20 rounded-full bg-gradient-to-r from-indigo-500 to-purple-600 flex items-center justify-center text-white font-bold text-2xl shadow-lg">
                {selectedStaff.name.charAt(0).toUpperCase()}
              </div>
              <div className="text-center sm:text-left">
                <h3 className="text-2xl font-bold text-gray-800">{selectedStaff.name}</h3>
                <p className="text-lg text-gray-600 mb-2">{selectedStaff.role}</p>
                <span className={`inline-flex px-3 py-1 text-sm font-semibold rounded-full ${
                  selectedStaff.role === 'Admin' 
                    ? 'bg-purple-100 text-purple-800' 
                    : 'bg-blue-100 text-blue-800'
                }`}>
                  {selectedStaff.role === 'Admin' ? 'Administrator' : 'Staff Member'}
                </span>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4">
              <div className="bg-gray-50 rounded-xl p-6">
                <h4 className="font-semibold mb-4 text-gray-800 text-lg flex items-center">
                  <UserIcon size={20} className="mr-2 text-indigo-600" />
                  Personal Information
                </h4>
                <div className="space-y-3">
                  <div className="flex items-center text-gray-700">
                    <span className="w-6 h-6 mr-3 flex items-center justify-center text-gray-500 bg-white rounded-full text-sm font-semibold">
                      G
                    </span>
                    <span><strong>Gender:</strong> {selectedStaff.gender}</span>
                  </div>
                  <div className="flex items-center text-gray-700">
                    <span className="w-6 h-6 mr-3 flex items-center justify-center text-gray-500 bg-white rounded-full text-sm font-semibold">
                      A
                    </span>
                    <span><strong>Age:</strong> {selectedStaff.age} years</span>
                  </div>
                  <div className="flex items-center text-gray-700">
                    <CakeIcon size={18} className="mr-3 text-gray-500" />
                    <span>
                      <strong>Birthday:</strong>{' '}
                      {new Date(selectedStaff.birthday).toLocaleDateString()}
                    </span>
                  </div>
                  <div className="flex items-center text-gray-700">
                    <ShieldIcon size={18} className="mr-3 text-gray-500" />
                    <span><strong>NIC:</strong> {selectedStaff.nic}</span>
                  </div>
                </div>
              </div>
              
              <div className="bg-gray-50 rounded-xl p-6">
                <h4 className="font-semibold mb-4 text-gray-800 text-lg flex items-center">
                  <PhoneIcon size={20} className="mr-2 text-indigo-600" />
                  Contact Information
                </h4>
                <div className="space-y-3">
                  <div className="flex items-center text-gray-700">
                    <MailIcon size={18} className="mr-3 text-gray-500" />
                    <span className="break-all">{selectedStaff.email}</span>
                  </div>
                  <div className="flex items-center text-gray-700">
                    <PhoneIcon size={18} className="mr-3 text-gray-500" />
                    <span>{selectedStaff.phone}</span>
                  </div>
                  <div className="flex items-start text-gray-700">
                    <MapPinIcon size={18} className="mr-3 mt-1 text-gray-500 flex-shrink-0" />
                    <span>{selectedStaff.address}</span>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl p-6">
              <h4 className="font-semibold mb-4 text-gray-800 text-lg flex items-center">
                <KeyIcon size={20} className="mr-2 text-indigo-600" />
                System Access
              </h4>
              <div className="flex items-center justify-between">
                <div className="space-y-2">
                  <div className="flex items-center">
                    <span className="font-medium text-gray-700 mr-2">Username:</span>
                    <span className="px-3 py-1 bg-white rounded-lg text-gray-800 font-mono">{selectedStaff.username}</span>
                  </div>
                  <div className="flex items-center">
                    <span className="font-medium text-gray-700 mr-2">Password:</span>
                    <span className="px-3 py-1 bg-white rounded-lg text-gray-400">••••••••</span>
                  </div>
                </div>
                <Button 
                  variant="outline" 
                  size="sm" 
                  icon={<KeyIcon size={14} />}
                  className="hover:bg-indigo-50 hover:border-indigo-300 hover:text-indigo-600 transition-all duration-200"
                >
                  Reset Password
                </Button>
              </div>
            </div>
            
            <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
              <Button 
                variant="outline" 
                onClick={() => setIsViewModalOpen(false)}
                className="px-6 py-3 hover:bg-gray-50 transition-all duration-200"
              >
                Close
              </Button>
              <Button 
                variant="primary" 
                onClick={() => {
                  setIsViewModalOpen(false);
                  setIsEditModalOpen(true);
                }}
                className="px-6 py-3 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 shadow-lg hover:shadow-xl transition-all duration-200"
              >
                Edit Personnel
              </Button>
            </div>
          </div>
        )}
      </Modal>
      {/* Add Staff Modal */}
      <Modal isOpen={isAddModalOpen} onClose={() => setIsAddModalOpen(false)} title="Add New Personnel" size="lg">
        <div className="mb-6">
          <p className="text-gray-600">Add a new team member with their personal and system access information.</p>
        </div>
        <form className="space-y-6" onSubmit={async (e) => {
          e.preventDefault();
          const form = e.target as HTMLFormElement;
          const formData = new FormData(form);
          const personnelInfo = {
            fullName: formData.get('fullName'),
            gender: formData.get('gender'),
            age: Number(formData.get('age')),
            birthDay: formData.get('birthDay'),
            nic: formData.get('nic'),
            contact: formData.get('contact'),
            adress: formData.get('adress'),
            email: formData.get('email'),
            userName: formData.get('userName'),
            password: formData.get('password'),
            role: formData.get('role'),
          };
          try {
            const token = localStorage.getItem('authToken');
            const baseUrl = import.meta.env.VITE_API_BASE_URL;
            await axios.post(`${baseUrl}/api/personnel/register`, { personnelInfo }, {
              headers: {
                Authorization: token ? `Bearer ${token}` : undefined,
              },
            });
            
            addToast('success', 'Personnel Added!', `${personnelInfo.fullName} has been successfully added to the team.`);
            setIsAddModalOpen(false);
            fetchStaffMembers();
          } catch (err) {
            addToast('error', 'Failed to Add Personnel', 'There was an error adding the personnel. Please try again.');
          }
        }}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label htmlFor="fullName" className="block text-sm font-semibold text-gray-700 mb-2">
                Full Name
              </label>
              <input 
                type="text" 
                id="fullName" 
                name="fullName" 
                className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all duration-200 hover:border-gray-400" 
                placeholder="Enter full name" 
                required
              />
            </div>
            <div>
              <label htmlFor="gender" className="block text-sm font-semibold text-gray-700 mb-2">
                Gender
              </label>
              <select 
                id="gender" 
                name="gender" 
                className="admin-dropdown w-full"
                required
              >
                <option value="">Select gender</option>
                <option value="Male">Male</option>
                <option value="Female">Female</option>
                <option value="Other">Other</option>
              </select>
            </div>
            <div>
              <label htmlFor="age" className="block text-sm font-medium text-gray-700 mb-1">
                Age
              </label>
              <input type="number" id="age" name="age" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="Enter age" />
            </div>
            <div>
              <label htmlFor="birthday" className="block text-sm font-medium text-gray-700 mb-1">
                Birthday
              </label>
              <input type="date" id="birthday" name="birthDay" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" />
            </div>
            <div>
              <label htmlFor="nic" className="block text-sm font-medium text-gray-700 mb-1">
                NIC
              </label>
              <input type="text" id="nic" name="nic" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="Enter NIC number" />
            </div>
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                Email
              </label>
              <input type="email" id="email" name="email" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="Enter email address" />
            </div>
            <div>
              <label htmlFor="phone" className="block text-sm font-medium text-gray-700 mb-1">
                Phone
              </label>
              <input type="tel" id="phone" name="contact" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="Enter phone number" />
            </div>
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                Username
              </label>
              <input type="text" id="username" name="userName" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="Enter username" />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <div className="relative">
                <input type={showPassword ? 'text' : 'password'} id="password" name="password" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent pr-10" placeholder="Enter password" />
                <button type="button" className="absolute inset-y-0 right-0 pr-3 flex items-center" onClick={() => setShowPassword(!showPassword)}>
                  {showPassword ? <EyeOffIcon size={18} className="text-gray-400" /> : <EyeIcon size={18} className="text-gray-400" />}
                </button>
              </div>
            </div>
            <div>
              <label htmlFor="role" className="block text-sm font-medium text-gray-700 mb-1">
                Role
              </label>
              <select id="role" name="role" className="admin-dropdown admin-dropdown-success w-full">
                <option value="Admin">Admin</option>
                <option value="Staff">Staff</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <label htmlFor="address" className="block text-sm font-medium text-gray-700 mb-1">
                Address
              </label>
              <textarea id="address" name="adress" rows={2} className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="Enter address"></textarea>
            </div>
          </div>
          <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
            <Button 
              variant="outline" 
              onClick={() => setIsAddModalOpen(false)}
              className="px-6 py-3 hover:bg-gray-50 transition-all duration-200"
            >
              Cancel
            </Button>
            <Button 
              type="submit" 
              variant="primary"
              className="px-6 py-3 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 shadow-lg hover:shadow-xl transition-all duration-200"
            >
              Add Personnel
            </Button>
          </div>
        </form>
      </Modal>
      {/* Edit Staff Modal */}
      <Modal isOpen={isEditModalOpen} onClose={() => setIsEditModalOpen(false)} title="Edit Personnel" size="lg">
        {selectedStaff && (
          <div>
            <div className="mb-6">
              <p className="text-gray-600">Update personnel information below. Changes will be reflected immediately.</p>
            </div>
            <form className="space-y-6" onSubmit={async (e) => {
          e.preventDefault();
          const form = e.target as HTMLFormElement;
          const formData = new FormData(form);
          // Helper to get value or fallback to current
          const getValue = (key: string, fallback: any) => {
            const val = formData.get(key);
            return (val === null || val === undefined || val === '') ? fallback : val;
          };
          // Build the full user data object with backend field names
          const updatingId = selectedStaff.id;
          const fullUserData: any = {
            _id: updatingId, // Backend expects _id
            fullName: getValue('edit-name', selectedStaff.name),
            gender: getValue('edit-gender', selectedStaff.gender),
            age: Number(getValue('edit-age', selectedStaff.age)),
            birthDay: getValue('edit-birthday', selectedStaff.birthday),
            nic: getValue('edit-nic', selectedStaff.nic),
            contact: getValue('edit-phone', selectedStaff.phone),
            adress: getValue('edit-address', selectedStaff.address),
            email: getValue('edit-email', selectedStaff.email),
            userName: getValue('edit-username', selectedStaff.username),
            role: getValue('edit-role', selectedStaff.role),
          };
          // Only add password if user entered a new one (future-proof, but not used now)
          const newPassword = formData.get('edit-password');
          if (newPassword && typeof newPassword === 'string' && newPassword.trim() !== '') {
            fullUserData.password = newPassword;
          }
          console.log('PATCH payload:', fullUserData); // Debug: log payload
          setLoading(true);
          try {
            const token = localStorage.getItem('authToken');
            const baseUrl = import.meta.env.VITE_API_BASE_URL;
            await axios.patch(`${baseUrl}/api/personnel/UpdatePersonnel/${updatingId}`,
              { updateData: fullUserData }, // wrap in updateData for backend compatibility
              {
                headers: {
                  Authorization: token ? `Bearer ${token}` : undefined,
                },
              }
            );
            addToast('success', 'Personnel Updated!', `${selectedStaff.name}'s information has been successfully updated.`);
            setIsEditModalOpen(false);
            fetchStaffMembers();
          } catch (err: any) {
            addToast('error', 'Failed to Update Personnel', 'There was an error updating the personnel information.');
          }
        }}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label htmlFor="edit-name" className="block text-sm font-medium text-gray-700 mb-1">
                Full Name
              </label>
              <input type="text" id="edit-name" name="edit-name" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedStaff.name} />
            </div>
            <div>
              <label htmlFor="edit-gender" className="block text-sm font-medium text-gray-700 mb-1">
                Gender
              </label>
              <select id="edit-gender" name="edit-gender" className="admin-dropdown admin-dropdown-success w-full" defaultValue={selectedStaff.gender}>
                <option value="Male">Male</option>
                <option value="Female">Female</option>
                <option value="Other">Other</option>
              </select>
            </div>
            <div>
              <label htmlFor="edit-age" className="block text-sm font-medium text-gray-700 mb-1">
                Age
              </label>
              <input type="number" id="edit-age" name="edit-age" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedStaff.age} />
            </div>
            <div>
              <label htmlFor="edit-birthday" className="block text-sm font-medium text-gray-700 mb-1">
                Birthday
              </label>
              <input type="date" id="edit-birthday" name="edit-birthday" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedStaff.birthday} />
            </div>
            <div>
              <label htmlFor="edit-nic" className="block text-sm font-medium text-gray-700 mb-1">
                NIC
              </label>
              <input type="text" id="edit-nic" name="edit-nic" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedStaff.nic} />
            </div>
            <div>
              <label htmlFor="edit-email" className="block text-sm font-medium text-gray-700 mb-1">
                Email
              </label>
              <input type="email" id="edit-email" name="edit-email" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedStaff.email} />
            </div>
            <div>
              <label htmlFor="edit-phone" className="block text-sm font-medium text-gray-700 mb-1">
                Phone
              </label>
              <input type="tel" id="edit-phone" name="edit-phone" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedStaff.phone} />
            </div>
            <div>
              <label htmlFor="edit-username" className="block text-sm font-medium text-gray-700 mb-1">
                Username
              </label>
              <input type="text" id="edit-username" name="edit-username" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedStaff.username} />
            </div>
            <div>
              <label htmlFor="edit-role" className="block text-sm font-medium text-gray-700 mb-1">
                Role
              </label>
              <select id="edit-role" name="edit-role" className="admin-dropdown admin-dropdown-success w-full" defaultValue={selectedStaff.role}>
                <option value="Admin">Admin</option>
                <option value="Staff">Staff</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <label htmlFor="edit-address" className="block text-sm font-medium text-gray-700 mb-1">
                Address
              </label>
              <textarea id="edit-address" name="edit-address" rows={2} className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedStaff.address}></textarea>
            </div>
          </div>
          <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
            <Button 
              variant="outline" 
              onClick={() => setIsEditModalOpen(false)}
              className="px-6 py-3 hover:bg-gray-50 transition-all duration-200"
            >
              Cancel
            </Button>
            <Button 
              type="submit" 
              variant="primary"
              className="px-6 py-3 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 shadow-lg hover:shadow-xl transition-all duration-200"
            >
              Update Personnel
            </Button>
          </div>
        </form>
          </div>
        )}
      </Modal>
      {/* Delete Confirmation Modal */}
      <Modal isOpen={isDeleteModalOpen} onClose={() => setIsDeleteModalOpen(false)} title="Delete Personnel">
        {selectedStaff && (
          <div className="text-center">
            <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-red-100 mb-6">
              <TrashIcon size={32} className="text-red-600" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900 mb-2">
              Are you sure you want to delete this personnel record?
            </h3>
            <p className="text-gray-600 mb-1">
              You're about to delete <strong>{selectedStaff.name}</strong>
            </p>
            <p className="text-sm text-gray-500 mb-8">
              This action cannot be undone and will remove all access permissions.
            </p>
            <div className="flex justify-center space-x-4">
              <Button 
                variant="outline" 
                onClick={() => setIsDeleteModalOpen(false)}
                className="px-6 py-3 hover:bg-gray-50 transition-all duration-200"
              >
                Cancel
              </Button>
              <Button 
                variant="danger" 
                onClick={async () => {
                  if (!selectedStaff) return;
                  try {
                    const token = localStorage.getItem('authToken');
                    const baseUrl = import.meta.env.VITE_API_BASE_URL;
                    await axios.delete(`${baseUrl}/api/personnel/deletePersonnel/${selectedStaff.id}`, {
                      headers: {
                        Authorization: token ? `Bearer ${token}` : undefined,
                      },
                    });
                    addToast('success', 'Personnel Deleted!', `${selectedStaff.name} has been successfully removed from the system.`);
                    setIsDeleteModalOpen(false);
                    fetchStaffMembers();
                  } catch (err) {
                    addToast('error', 'Failed to Delete Personnel', 'There was an error deleting the personnel record.');
                  }
                }}
                className="px-6 py-3 bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 shadow-lg hover:shadow-xl transition-all duration-200"
              >
                Delete Personnel
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
export default StaffManager;