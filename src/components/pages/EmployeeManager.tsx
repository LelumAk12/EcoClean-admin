/// <reference types="vite/client" />
import React, { useState, useEffect } from 'react';
import { SearchIcon, EditIcon, TrashIcon, UserIcon, PhoneIcon, MailIcon, UserPlusIcon, ShieldIcon, EyeIcon, XIcon, AlertCircleIcon, CheckCircleIcon, XCircleIcon, UsersIcon, UserCheckIcon, UserXIcon, ClockIcon } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import Button from '../common/Button';
import Modal from '../common/Modal';
import axios from 'axios';
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

interface Employee {
  id: number;
  firstName: string;
  lastName: string;
  gender: 'Male' | 'Female' | 'Other';
  age: number;
  birthday: string;
  nic: string;
  email: string;
  phone: string;
  address: string;
  monthlySalary: number;
  totalSalary: number;
  role: string;
  status: 'Active' | 'Inactive' | 'On Leave';
  avatar?: string;
}

const EmployeeManager = () => {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [selectedEmployee, setSelectedEmployee] = useState<Employee | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [employees, setEmployees] = useState<Employee[]>([]);
  const [loading, setLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const itemsPerPage = 5;

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

  // Employee Card Component
  const EmployeeCard = ({ employee, index, onView, onEdit, onDelete }: { 
    employee: Employee; 
    index: number; 
    onView: () => void; 
    onEdit: () => void;
    onDelete: () => void; 
  }) => {
    const getStatusColor = () => {
      switch (employee.status) {
        case 'Active':
          return 'bg-green-100 text-green-800 border-green-200';
        case 'On Leave':
          return 'bg-yellow-100 text-yellow-800 border-yellow-200';
        default:
          return 'bg-red-100 text-red-800 border-red-200';
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
              <div className="h-14 w-14 rounded-full overflow-hidden bg-gradient-to-br from-gray-100 to-gray-200">
                {employee.avatar ? (
                  <img 
                    className="h-full w-full object-cover" 
                    src={employee.avatar} 
                    alt={`${employee.firstName} ${employee.lastName}`}
                    onError={(e) => {
                      e.currentTarget.style.display = 'none';
                      e.currentTarget.nextElementSibling?.classList.remove('hidden');
                    }}
                  />
                ) : null}
                <div className={`h-full w-full flex items-center justify-center ${employee.avatar ? 'hidden' : ''}`}>
                  <UserIcon size={24} className="text-gray-500" />
                </div>
              </div>
              <div className={`absolute -bottom-1 -right-1 h-4 w-4 rounded-full border-2 border-white ${employee.status === 'Active' ? 'bg-green-500' : employee.status === 'On Leave' ? 'bg-yellow-500' : 'bg-red-500'}`}></div>
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="text-lg font-semibold text-gray-900 truncate group-hover:text-blue-600 transition-colors duration-200">
                {`${employee.firstName} ${employee.lastName}`}
              </h3>
              <p className="text-sm text-gray-500 truncate">
                {employee.role}
              </p>
              <div className="flex items-center text-xs text-gray-400 mt-1">
                <MailIcon size={12} className="mr-1" />
                <span className="truncate">{employee.email}</span>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap gap-2 mb-4">
            <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getStatusColor()}`}>
              {employee.status}
            </span>
          </div>

          <div className="text-xs text-gray-500 mb-4 space-y-1">
            <div className="flex items-center">
              <PhoneIcon size={12} className="mr-2" />
              <span>{employee.phone}</span>
            </div>
            <div className="flex items-center">
              <ShieldIcon size={12} className="mr-2" />
              <span className="font-mono">{employee.nic}</span>
            </div>
          </div>

          <div className="flex space-x-2">
            <Button
              variant="outline"
              size="sm"
              icon={<EyeIcon size={16} />}
              onClick={onView}
              className="flex-1 hover:bg-blue-50 hover:border-blue-200 hover:text-blue-700 transition-all duration-200"
            >
              View
            </Button>
            <Button
              variant="outline"
              size="sm"
              icon={<EditIcon size={16} />}
              onClick={onEdit}
              className="hover:bg-green-50 hover:border-green-200 hover:text-green-700 transition-all duration-200"
            >
              Edit
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

  const fetchEmployees = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('authToken');
      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      const response = await axios.get(`${baseUrl}/api/personnel/all-employees`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      const apiEmployees = response.data.data;
      const mappedEmployees: Employee[] = apiEmployees.map((emp: any) => ({
        id: emp._id,
        firstName: emp.fullName?.split(' ')[0] || '',
        lastName: emp.fullName?.split(' ').slice(1).join(' ') || '',
        gender: emp.gender || 'Other',
        age: emp.age || 0,
        birthday: emp.birthDay || '',
        nic: emp.nic || '',
        email: emp.email || '',
        phone: emp.contact || '',
        address: emp.adress || '',
        monthlySalary: emp.monthlySalary || 0,
        totalSalary: emp.totalSalary || 0,
        role: emp.role || '',
        status: emp.status || 'Active',
        avatar: emp.avatar || '',
      }));
      setEmployees(mappedEmployees);
    } catch (err: any) {
      addToast('error', 'Failed to Load Employees', 'Unable to fetch employee data from the server.');
    } finally {
      setLoading(false);
    }
  };

  const filteredEmployees = employees.filter(employee => 
    (statusFilter === 'all' || employee.status === statusFilter) && 
    (`${employee.firstName} ${employee.lastName}`.toLowerCase().includes(searchTerm.toLowerCase()) || 
     employee.email.toLowerCase().includes(searchTerm.toLowerCase()) || 
     employee.nic.toLowerCase().includes(searchTerm.toLowerCase()) || 
     employee.role.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  // Pagination logic
  const indexOfLastEmployee = currentPage * itemsPerPage;
  const indexOfFirstEmployee = indexOfLastEmployee - itemsPerPage;
  const totalPages = Math.ceil(filteredEmployees.length / itemsPerPage);

  const handleAddEmployee = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsSubmitting(true);
    try {
      const form = event.target as HTMLFormElement;
      const getValue = (name: string) =>
        (form.elements.namedItem(name) as HTMLInputElement | HTMLSelectElement)?.value || '';
      const fullName = getValue('firstName') + ' ' + getValue('lastName');
      const payload = {
        fullName,
        gender: getValue('gender'),
        age: Number(getValue('age')) || 0,
        birthDay: getValue('birthday'),
        nic: getValue('nic'),
        contact: getValue('phone'),
        adress: getValue('address'),
        email: getValue('email'),
        role: 'Employee',
      };
      const token = localStorage.getItem('authToken');
      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      await axios.post(`${baseUrl}/api/personnel/create-employee`, payload, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      
      setIsAddModalOpen(false);
      addToast('success', 'Employee Added', `${fullName} has been successfully added to the system.`);
      
      // Refresh employee list
      await fetchEmployees();
      
      // Reset form
      form.reset();
    } catch (err: any) {
      addToast('error', 'Add Failed', err.response?.data?.message || 'Unable to add employee. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEditEmployee = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedEmployee) return;
    setIsSubmitting(true);
    try {
      const form = event.target as HTMLFormElement;
      const getValue = (name: string) =>
        (form.elements.namedItem(name) as HTMLInputElement | HTMLSelectElement)?.value || '';
      const fullName = getValue('firstName') + ' ' + getValue('lastName');
      const payload = {
        fullName,
        gender: getValue('gender'),
        age: Number(getValue('age')) || 0,
        birthDay: getValue('birthday'),
        nic: getValue('nic'),
        contact: getValue('phone'),
        adress: getValue('address'),
        email: getValue('email'),
        role: getValue('role'),
      };
      const token = localStorage.getItem('authToken');
      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      await axios.put(`${baseUrl}/api/personnel/update-employee/${selectedEmployee.id}`, payload, {
        headers: { Authorization: `Bearer ${token}` },
      });
      
      setIsEditModalOpen(false);
      setSelectedEmployee(null);
      addToast('success', 'Employee Updated', `${fullName} has been successfully updated.`);
      
      // Refresh employee list
      await fetchEmployees();
    } catch (err: any) {
      addToast('error', 'Update Failed', err.response?.data?.message || 'Unable to update employee. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteEmployee = async () => {
    if (!selectedEmployee) return;
    setIsSubmitting(true);
    try {
      const token = localStorage.getItem('authToken');
      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      await axios.delete(`${baseUrl}/api/personnel/delete-employee/${selectedEmployee.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      
      setIsDeleteModalOpen(false);
      setSelectedEmployee(null);
      addToast('success', 'Employee Deleted', `${selectedEmployee.firstName} ${selectedEmployee.lastName} has been successfully removed from the system.`);
      
      // Refresh employee list
      await fetchEmployees();
    } catch (err: any) {
      addToast('error', 'Delete Failed', err.response?.data?.message || 'Unable to delete employee. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  useEffect(() => {
    fetchEmployees();
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-orange-50 to-amber-50 p-6">
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
              <div className="bg-gradient-to-r from-orange-500 to-amber-600 p-3 rounded-xl">
                <UsersIcon size={28} className="text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-orange-900 to-amber-900 bg-clip-text text-transparent">
                  Employee Management
                </h1>
                <p className="text-gray-500 mt-1">Manage your team members and their information</p>
              </div>
            </div>
            <div className="flex flex-col sm:flex-row gap-3 w-full lg:w-auto">
              <Button 
                variant="primary" 
                icon={<UserPlusIcon size={18} />} 
                onClick={() => setIsAddModalOpen(true)}
                className="bg-gradient-to-r from-orange-500 to-amber-600 hover:from-orange-600 hover:to-amber-700 shadow-lg hover:shadow-xl transition-all duration-200"
              >
                Add Employee
              </Button>
            </div>
          </div>
        </motion.div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <motion.div 
            {...pageAnimations.statsCard(0)}
            className="relative bg-gradient-to-br from-blue-50 via-white to-blue-100 rounded-2xl shadow-lg border border-blue-100 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-transparent to-indigo-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-blue-500 to-indigo-600 p-3 rounded-xl shadow-lg">
                  <UsersIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-blue-600 bg-blue-100 px-2 py-1 rounded-full">
                    Total
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Total Employees</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                  {employees.length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-blue-500 to-indigo-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((employees.length / Math.max(employees.length, 10)) * 100, 100)}%` }}
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
                  {employees.filter(emp => emp.status === 'Active').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-green-500 to-emerald-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((employees.filter(emp => emp.status === 'Active').length / Math.max(employees.length, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>

          <motion.div 
            {...pageAnimations.statsCard(2)}
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
                    On Leave
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">On Leave</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-yellow-600 to-orange-600 bg-clip-text text-transparent">
                  {employees.filter(emp => emp.status === 'On Leave').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-yellow-500 to-orange-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((employees.filter(emp => emp.status === 'On Leave').length / Math.max(employees.length, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>

          <motion.div 
            {...pageAnimations.statsCard(3)}
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
                  {employees.filter(emp => emp.status === 'Inactive').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-red-500 to-pink-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((employees.filter(emp => emp.status === 'Inactive').length / Math.max(employees.length, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Main Content Card */}
        <div className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden">
          {/* Enhanced Search and Filter Section */}
          <div className="p-6 border-b border-gray-200 bg-gradient-to-r from-gray-50 to-white">
            <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center space-y-4 lg:space-y-0">
              <div className="flex-1 max-w-md">
                <div className="relative">
                  <SearchIcon size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                  <input 
                    type="text" 
                    placeholder="Search employees by name, role, or email..." 
                    className="w-full pl-10 pr-4 py-3 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white shadow-sm hover:border-gray-300 transition-colors duration-200" 
                    value={searchTerm} 
                    onChange={e => setSearchTerm(e.target.value)} 
                  />
                </div>
              </div>
              <div className="flex flex-wrap gap-3">
                <select 
                  value={statusFilter} 
                  onChange={e => setStatusFilter(e.target.value)} 
                  className="admin-dropdown admin-dropdown-warning"
                >
                  <option value="all">All Statuses</option>
                  <option value="Active">Active</option>
                  <option value="On Leave">On Leave</option>
                  <option value="Inactive">Inactive</option>
                </select>
              </div>
            </div>
          </div>
          {/* Employee Content */}
          <div className="p-6">
            {/* Employees Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {loading ? (
                // Loading skeleton
                Array.from({ length: 6 }).map((_, index) => (
                  <div key={index} className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden animate-pulse">
                    <div className="p-6">
                      <div className="flex items-center space-x-4 mb-4">
                        <div className="h-14 w-14 bg-gray-200 rounded-full"></div>
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
                  {filteredEmployees.slice(indexOfFirstEmployee, indexOfLastEmployee).map((employee, index) => (
                    <EmployeeCard 
                      key={employee.id} 
                      employee={employee} 
                      index={index}
                      onView={() => {
                        setSelectedEmployee(employee);
                        setIsViewModalOpen(true);
                      }}
                      onEdit={() => {
                        setSelectedEmployee(employee);
                        setIsEditModalOpen(true);
                      }}
                      onDelete={() => {
                        setSelectedEmployee(employee);
                        setIsDeleteModalOpen(true);
                      }}
                    />
                  ))}
                  {filteredEmployees.length === 0 && (
                    <div className="col-span-3 py-16 text-center">
                      <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-12">
                        <UsersIcon size={64} className="mx-auto mb-6 text-gray-300" />
                        <h3 className="text-xl font-semibold text-gray-600 mb-2">
                          No employees found
                        </h3>
                        <p className="text-gray-500">
                          No employees match your current filter criteria. Try adjusting your filters or add a new employee.
                        </p>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>

            {/* Pagination */}
            {!loading && filteredEmployees.length > 0 && (
              <div className="mt-6 pt-6 border-t border-gray-200">
                <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
                  <p className="text-sm text-gray-500">
                    Showing {indexOfFirstEmployee + 1}-
                    {Math.min(indexOfLastEmployee, filteredEmployees.length)} of{' '}
                    {filteredEmployees.length} employees
                  </p>
                  <div className="flex space-x-2">
                    <Button 
                      variant="outline" 
                      size="sm" 
                      disabled={currentPage === 1} 
                      onClick={() => setCurrentPage(currentPage - 1)}
                      className="hover:bg-orange-50 hover:border-orange-200 hover:text-orange-700"
                    >
                      Previous
                    </Button>
                    {Array.from({ length: totalPages }, (_, i) => i + 1).map(page => (
                      <Button
                        key={page}
                        variant={page === currentPage ? "primary" : "outline"}
                        size="sm"
                        onClick={() => setCurrentPage(page)}
                        className={page === currentPage 
                          ? "bg-gradient-to-r from-orange-500 to-amber-600 text-white" 
                          : "hover:bg-orange-50 hover:border-orange-200 hover:text-orange-700"
                        }
                      >
                        {page}
                      </Button>
                    ))}
                    <Button 
                      variant="outline" 
                      size="sm" 
                      disabled={currentPage === totalPages} 
                      onClick={() => setCurrentPage(currentPage + 1)}
                      className="hover:bg-orange-50 hover:border-orange-200 hover:text-orange-700"
                    >
                      Next
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Add Employee Modal */}
        <Modal isOpen={isAddModalOpen} onClose={() => setIsAddModalOpen(false)} title="Add New Employee">
          <form onSubmit={handleAddEmployee} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label htmlFor="firstName" className="block text-sm font-medium text-gray-700 mb-1">
                  First Name *
                </label>
                <input type="text" name="firstName" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent" required />
              </div>
              <div>
                <label htmlFor="lastName" className="block text-sm font-medium text-gray-700 mb-1">
                  Last Name *
                </label>
                <input type="text" name="lastName" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent" required />
              </div>
              <div>
                <label htmlFor="gender" className="block text-sm font-medium text-gray-700 mb-1">
                  Gender *
                </label>
                <select name="gender" className="admin-dropdown admin-dropdown-warning w-full" required>
                  <option value="">Select Gender</option>
                  <option value="Male">Male</option>
                  <option value="Female">Female</option>
                  <option value="Other">Other</option>
                </select>
              </div>
              <div>
                <label htmlFor="birthday" className="block text-sm font-medium text-gray-700 mb-1">
                  Birthday *
                </label>
                <input type="date" name="birthday" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent" required />
              </div>
              <div>
                <label htmlFor="age" className="block text-sm font-medium text-gray-700 mb-1">
                  Age *
                </label>
                <input type="number" name="age" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent" min={0} required />
              </div>
              <div>
                <label htmlFor="nic" className="block text-sm font-medium text-gray-700 mb-1">
                  NIC *
                </label>
                <input type="text" name="nic" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent" required />
              </div>
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                  Email *
                </label>
                <input type="email" name="email" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent" required />
              </div>
              <div>
                <label htmlFor="phone" className="block text-sm font-medium text-gray-700 mb-1">
                  Phone *
                </label>
                <input type="tel" name="phone" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent" required />
              </div>
              <div className="md:col-span-2">
                <label htmlFor="address" className="block text-sm font-medium text-gray-700 mb-1">
                  Address *
                </label>
                <textarea name="address" rows={2} className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent" required></textarea>
              </div>
            </div>
            <div className="flex justify-end space-x-3 pt-4">
              <Button variant="outline" type="button" onClick={() => setIsAddModalOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={isSubmitting}>
                {isSubmitting ? 'Adding...' : 'Add Employee'}
              </Button>
            </div>
          </form>
        </Modal>

        {/* View Employee Modal */}
        <Modal isOpen={isViewModalOpen} onClose={() => setIsViewModalOpen(false)} title="Employee Details">
          {selectedEmployee && (
            <div className="space-y-6">
              <div className="flex items-center space-x-4 pb-4 border-b border-gray-200">
                <div className="h-16 w-16 rounded-full overflow-hidden bg-gradient-to-br from-gray-100 to-gray-200">
                  {selectedEmployee.avatar ? (
                    <img className="h-full w-full object-cover" src={selectedEmployee.avatar} alt={`${selectedEmployee.firstName} ${selectedEmployee.lastName}`} />
                  ) : (
                    <div className="h-full w-full flex items-center justify-center">
                      <UserIcon size={32} className="text-gray-500" />
                    </div>
                  )}
                </div>
                <div>
                  <h3 className="text-xl font-semibold text-gray-900">
                    {selectedEmployee.firstName} {selectedEmployee.lastName}
                  </h3>
                  <p className="text-gray-600">{selectedEmployee.role}</p>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium mt-1 ${
                    selectedEmployee.status === 'Active' 
                      ? 'bg-green-100 text-green-800' 
                      : selectedEmployee.status === 'On Leave'
                      ? 'bg-yellow-100 text-yellow-800'
                      : 'bg-red-100 text-red-800'
                  }`}>
                    {selectedEmployee.status}
                  </span>
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-500">Gender</label>
                  <p className="text-gray-900">{selectedEmployee.gender}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-500">Age</label>
                  <p className="text-gray-900">{selectedEmployee.age} years</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-500">Birthday</label>
                  <p className="text-gray-900">
                    {selectedEmployee.birthday 
                      ? new Date(selectedEmployee.birthday).toLocaleDateString('en-US', { 
                          year: 'numeric', 
                          month: 'long', 
                          day: 'numeric' 
                        })
                      : 'N/A'
                    }
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-500">NIC</label>
                  <p className="text-gray-900 font-mono">{selectedEmployee.nic}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-500">Email</label>
                  <p className="text-gray-900">{selectedEmployee.email}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-500">Phone</label>
                  <p className="text-gray-900">{selectedEmployee.phone}</p>
                </div>
                <div className="md:col-span-2">
                  <label className="text-sm font-medium text-gray-500">Address</label>
                  <p className="text-gray-900">{selectedEmployee.address}</p>
                </div>
              </div>
              
              <div className="flex justify-end space-x-3 pt-4">
                <Button variant="outline" onClick={() => setIsViewModalOpen(false)}>
                  Close
                </Button>
                <Button variant="primary" onClick={() => {
                  setIsViewModalOpen(false);
                  setIsEditModalOpen(true);
                }}>
                  Edit Employee
                </Button>
              </div>
            </div>
          )}
        </Modal>

        {/* Edit Employee Modal */}
        <Modal isOpen={isEditModalOpen} onClose={() => setIsEditModalOpen(false)} title="Edit Employee">
          {selectedEmployee && (
            <form onSubmit={handleEditEmployee} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="edit-firstName" className="block text-sm font-medium text-gray-700 mb-1">
                    First Name *
                  </label>
                  <input type="text" name="firstName" id="edit-firstName" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedEmployee.firstName} required />
                </div>
                <div>
                  <label htmlFor="edit-lastName" className="block text-sm font-medium text-gray-700 mb-1">
                    Last Name *
                  </label>
                  <input type="text" name="lastName" id="edit-lastName" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedEmployee.lastName} required />
                </div>
                <div>
                  <label htmlFor="edit-gender" className="block text-sm font-medium text-gray-700 mb-1">
                    Gender *
                  </label>
                  <select name="gender" id="edit-gender" className="admin-dropdown admin-dropdown-success w-full" defaultValue={selectedEmployee.gender} required>
                    <option value="Male">Male</option>
                    <option value="Female">Female</option>
                    <option value="Other">Other</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="edit-birthday" className="block text-sm font-medium text-gray-700 mb-1">
                    Birthday *
                  </label>
                  <input type="date" name="birthday" id="edit-birthday" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedEmployee.birthday} required />
                </div>
                <div>
                  <label htmlFor="edit-age" className="block text-sm font-medium text-gray-700 mb-1">
                    Age *
                  </label>
                  <input type="number" name="age" id="edit-age" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedEmployee.age} min={0} required />
                </div>
                <div>
                  <label htmlFor="edit-nic" className="block text-sm font-medium text-gray-700 mb-1">
                    NIC *
                  </label>
                  <input type="text" name="nic" id="edit-nic" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedEmployee.nic} required />
                </div>
                <div>
                  <label htmlFor="edit-email" className="block text-sm font-medium text-gray-700 mb-1">
                    Email *
                  </label>
                  <input type="email" name="email" id="edit-email" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedEmployee.email} required />
                </div>
                <div>
                  <label htmlFor="edit-phone" className="block text-sm font-medium text-gray-700 mb-1">
                    Phone *
                  </label>
                  <input type="tel" name="phone" id="edit-phone" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedEmployee.phone} required />
                </div>
                <div className="md:col-span-2">
                  <label htmlFor="edit-address" className="block text-sm font-medium text-gray-700 mb-1">
                    Address *
                  </label>
                  <textarea name="address" id="edit-address" rows={2} className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" defaultValue={selectedEmployee.address} required></textarea>
                </div>
                <div>
                  <label htmlFor="edit-role" className="block text-sm font-medium text-gray-700 mb-1">
                    Role *
                  </label>
                  <select name="role" id="edit-role" className="admin-dropdown admin-dropdown-success w-full" defaultValue="Employee" required>
                    <option value="Employee">Employee</option>
                  </select>
                </div>
              </div>
              <div className="flex justify-end space-x-3 pt-4">
                <Button variant="outline" type="button" onClick={() => {
                  setIsEditModalOpen(false);
                  setIsSubmitting(false);
                }}>
                  Cancel
                </Button>
                <Button type="submit" variant="primary" disabled={isSubmitting}>
                  {isSubmitting ? 'Updating...' : 'Update Employee'}
                </Button>
              </div>
            </form>
          )}
        </Modal>

        {/* Delete Confirmation Modal */}
        <Modal isOpen={isDeleteModalOpen} onClose={() => setIsDeleteModalOpen(false)} title="Delete Employee">
          {selectedEmployee && (
            <div>
              <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-4">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <AlertCircleIcon className="h-5 w-5 text-red-400" />
                  </div>
                  <div className="ml-3">
                    <p className="text-sm text-red-700">
                      This action cannot be undone. This will permanently delete
                      the employee record and remove all associated data.
                    </p>
                  </div>
                </div>
              </div>
              <p className="text-gray-600">
                Are you sure you want to delete the employee record for{' '}
                <span className="font-medium">{`${selectedEmployee.firstName} ${selectedEmployee.lastName}`}</span>
                ?
              </p>
              <div className="mt-4 bg-gray-50 p-4 rounded-md">
                <h4 className="text-sm font-medium text-gray-700 mb-2">
                  Employee Information
                </h4>
                <ul className="text-sm text-gray-600 space-y-1">
                  <li>
                    <span className="font-medium">Name:</span>{' '}
                    {selectedEmployee.firstName} {selectedEmployee.lastName}
                  </li>
                  <li>
                    <span className="font-medium">Role:</span>{' '}
                    {selectedEmployee.role}
                  </li>
                  <li>
                    <span className="font-medium">Email:</span>{' '}
                    {selectedEmployee.email}
                  </li>
                </ul>
              </div>
              <div className="flex justify-end space-x-3 mt-6">
                <Button variant="outline" onClick={() => setIsDeleteModalOpen(false)}>
                  Cancel
                </Button>
                <Button variant="danger" onClick={handleDeleteEmployee} disabled={isSubmitting}>
                  {isSubmitting ? 'Deleting...' : 'Delete Employee'}
                </Button>
              </div>
            </div>
          )}
        </Modal>

      </div>
    </div>
  );
};

export default EmployeeManager;
