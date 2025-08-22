import { useState, useEffect } from 'react';
import { SearchIcon, EditIcon, TrashIcon, CheckIcon, XIcon, ImageIcon, MapPinIcon, PhoneIcon, DollarSignIcon, UserIcon, CheckCircleIcon, XCircleIcon, AlertCircleIcon, TruckIcon, CalendarIcon } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import Button from '../common/Button';
import Table from '../common/Table';
import Modal from '../common/Modal';
import { pageAnimations } from '../../utils/animations';

/// <reference types="vite/client" />
// Toast Notification Types
type ToastType = 'success' | 'error' | 'warning' | 'info';

interface Toast {
  id: string;
  type: ToastType;
  title: string;
  message: string;
}

interface PickupRequest {
  id: string;
  userName: string;
  contact: string;
  location: string;
  imageUrl: string;
  date: string;
  advance: number;
  price: number;
  balance: number;
  status: 'Pending' | 'In Progress' | 'Completed' | 'Canceled' | 'Confirmed';
  staff: string[];
  // Removed weight, recyclables, notes fields
}

interface Employee {
  id: string;
  fullName: string;
  position?: string;
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
      transition={{ duration: 0.3, ease: 'easeOut' }}
      className={`min-w-[320px] max-w-md w-full ${getToastColors()} border rounded-xl shadow-xl p-4 mb-2 backdrop-blur-sm`}
    >
      <div className="flex items-start">
        <div className="flex-shrink-0 mt-0.5">{getToastIcon()}</div>
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
          initial={{ width: '100%' }}
          animate={{ width: '0%' }}
          transition={{ duration: 6, ease: 'linear' }}
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

const PickupRequestManager = () => {
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [selectedService, setSelectedService] = useState<PickupRequest | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [serviceRequests, setServiceRequests] = useState<PickupRequest[]>([]);
  const [employees, setEmployees] = useState<Employee[]>([]);
  const [assignedEmployees, setAssignedEmployees] = useState<Employee[]>([]);
  const [selectedStaff, setSelectedStaff] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [currentAdvance, setCurrentAdvance] = useState<number>(0);
  const [currentBalance, setCurrentBalance] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(10);
  const [editFormData, setEditFormData] = useState({
    userName: '',
    contact: '',
    location: '',
    date: '',
    price: 0,
    advancePercentage: 0,
    status: 'Pending' as PickupRequest['status'],
  });

  // Toast helper functions
  const addToast = (type: ToastType, title: string, message: string) => {
    const newToast: Toast = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type,
      title,
      message,
    };
    setToasts((prev) => [...prev, newToast]);
  };

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  };

  // Fetch pickup requests
  useEffect(() => {
    const fetchServiceRequests = async () => {
      setLoading(true);
      setError(null);
      try {
        const token = localStorage.getItem('authToken');
        if (!token) throw new Error('No authentication token available');
        const baseUrl = import.meta.env.VITE_API_BASE_URL;
        const response = await fetch(`${baseUrl}/api/personnel/getall-bookings`, {
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        });
        const data = await response.json();
        if (data.success && Array.isArray(data.allBookings)) {
          setServiceRequests(
            data.allBookings.map((req: any) => ({
              id: req._id,
              userName: req.userName,
              contact: req.contact,
              location: req.location,
              imageUrl: req.imageUrl || '',
              date: req.date ? req.date.slice(0, 10) : '',
              advance: req.advance || 0,
              price: req.price || 0,
              balance: req.balance || (req.price && req.advance ? req.price - req.advance : 0),
              status: req.status,
              staff: req.staff || [],
            }))
          );
        } else {
          setServiceRequests([]);
          addToast('warning', 'No Data', data.message || 'No bookings found');
        }
      } catch (err: any) {
        addToast('error', 'Loading Failed', err.message || 'Failed to fetch bookings');
      } finally {
        setLoading(false);
      }
    };
    fetchServiceRequests();
  }, []);

  // Fetch employees
  useEffect(() => {
    const fetchEmployees = async () => {
      try {
        const token = localStorage.getItem('authToken');
        if (!token) throw new Error('No authentication token available');
        const baseUrl = import.meta.env.VITE_API_BASE_URL;
        const response = await fetch(`${baseUrl}/api/personnel/all-employees`, {
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        });
        const data = await response.json();
        if (data.success && Array.isArray(data.data)) {
          setEmployees(
            data.data.map((emp: any) => ({
              id: emp._id,
              fullName: emp.fullName,
              position: emp.position,
            }))
          );
        } else {
          setEmployees([]);
          addToast('warning', 'No Employees', data.message || 'No employees available for assignment');
        }
      } catch (err: any) {
        setEmployees([]);
        addToast('error', 'Loading Failed', err.message || 'Failed to fetch employees');
      }
    };
    fetchEmployees();
  }, []);

  // Fetch assigned employee details for view modal
  useEffect(() => {
    const fetchAssignedEmployees = async () => {
      if (selectedService && isViewModalOpen && selectedService.staff && selectedService.staff.length > 0) {
        try {
          const token = localStorage.getItem('authToken');
          if (!token) throw new Error('No authentication token available');
          const baseUrl = import.meta.env.VITE_API_BASE_URL;
          const details = await Promise.all(
            selectedService.staff.map(async (id: string) => {
              const res = await fetch(`${baseUrl}/api/personnel/get-employee/${id}`, {
                headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
              });
              const data = await res.json();
              return data.success ? data.data : null;
            })
          );
          setAssignedEmployees(details.filter(Boolean));
        } catch (err: any) {
          setAssignedEmployees([]);
          addToast('error', 'Loading Failed', err.message || 'Failed to fetch assigned employee details');
        }
      } else {
        setAssignedEmployees([]);
      }
    };
    fetchAssignedEmployees();
  }, [selectedService, isViewModalOpen]);

  // Initialize edit form and staff when modal opens
  useEffect(() => {
    if (selectedService && isEditModalOpen) {
      const currentAdvancePercent = selectedService.price > 0 && selectedService.advance > 0
        ? Math.round((selectedService.advance / selectedService.price) * 100)
        : 0;
      setEditFormData({
        userName: selectedService.userName || '',
        contact: selectedService.contact || '',
        location: selectedService.location || '',
        date: selectedService.date || '',
        price: selectedService.price || 0,
        advancePercentage: currentAdvancePercent,
        status: selectedService.status || 'Pending',
      });
      setCurrentAdvance(selectedService.advance || 0);
      setCurrentBalance(selectedService.balance || 0);
      setSelectedStaff(selectedService.staff || []);
    } else if (!isEditModalOpen) {
      setEditFormData({
        userName: '',
        contact: '',
        location: '',
        date: '',
        price: 0,
        advancePercentage: 0,
        status: 'Pending',
      });
      setCurrentAdvance(0);
      setCurrentBalance(0);
      setSelectedStaff([]);
    }
  }, [selectedService, isEditModalOpen]);

  // Update advance and balance when price or advance percentage changes
  useEffect(() => {
    if (isEditModalOpen && selectedService) {
      if (editFormData.advancePercentage > 0 && editFormData.price > 0) {
        const advance = Math.round((editFormData.advancePercentage / 100) * editFormData.price);
        const balance = editFormData.price - advance;
        setCurrentAdvance(advance);
        setCurrentBalance(balance);
      } else {
        setCurrentAdvance(selectedService.advance || 0);
        setCurrentBalance(selectedService.balance || 0);
      }
    }
  }, [editFormData.advancePercentage, editFormData.price, isEditModalOpen, selectedService]);

  const columns = [
    {
      header: 'User Name',
      accessor: 'userName',
      cell: (value: string) => (
        <div className="flex items-center">
          <UserIcon size={16} className="mr-2 text-gray-400" />
          <span>{value}</span>
        </div>
      ),
    },
    {
      header: 'Contact',
      accessor: 'contact',
      cell: (value: string) => (
        <div className="flex items-center">
          <PhoneIcon size={16} className="mr-2 text-gray-400" />
          <span>{value}</span>
        </div>
      ),
    },
    {
      header: 'Location',
      accessor: 'location',
      cell: (value: string) => (
        <div className="flex items-center">
          <MapPinIcon size={16} className="mr-2 text-gray-400" />
          <span>{value}</span>
        </div>
      ),
    },
    {
      header: 'Date',
      accessor: 'date',
      cell: (value: string) => (
        <div className="flex items-center">
          <CalendarIcon size={16} className="mr-2 text-gray-400" />
          {value ? new Date(value).toLocaleDateString() : 'N/A'}
        </div>
      ),
    },
    {
      header: 'Price',
      accessor: 'price',
      cell: (value: number) => (
        <div className="flex items-center">
          <DollarSignIcon size={16} className="mr-1 text-gray-400" />
          <span>LKR {value.toLocaleString()}</span>
        </div>
      ),
    },
    {
      header: 'Advance',
      accessor: 'advance',
      cell: (value: number) => (
        <div className="flex items-center">
          <DollarSignIcon size={16} className="mr-1 text-blue-400" />
          <span>LKR {value.toLocaleString()}</span>
        </div>
      ),
    },
    {
      header: 'Balance',
      accessor: 'balance',
      cell: (value: number) => (
        <div className="flex items-center">
          <DollarSignIcon size={16} className="mr-1 text-red-400" />
          <span>LKR {value.toLocaleString()}</span>
        </div>
      ),
    },
    {
      header: 'Status',
      accessor: 'status',
      cell: (value: string) => (
        <span
          className={`px-2 py-1 text-xs font-medium rounded-full ${
            value === 'Completed'
              ? 'bg-green-100 text-green-800'
              : value === 'Pending'
              ? 'bg-yellow-100 text-yellow-800'
              : value === 'In Progress'
              ? 'bg-blue-100 text-blue-800'
              : value === 'Confirmed'
              ? 'bg-purple-100 text-purple-800'
              : 'bg-red-100 text-red-800'
          }`}
        >
          {value}
        </span>
      ),
    },
    {
      header: 'Actions',
      accessor: 'id',
      cell: (_: any, row: PickupRequest) => (
        <div className="flex space-x-2">
          <Button
            variant="outline"
            size="sm"
            icon={<CheckIcon size={14} />}
            onClick={(e) => {
              e.stopPropagation();
              setSelectedService(row);
              setIsViewModalOpen(true);
            }}
          >
            View
          </Button>
          <Button
            variant="outline"
            size="sm"
            icon={<EditIcon size={14} />}
            onClick={(e) => {
              e.stopPropagation();
              setSelectedService(row);
              setIsEditModalOpen(true);
            }}
          >
            Edit
          </Button>
          <Button
            variant="danger"
            size="sm"
            icon={<TrashIcon size={14} />}
            onClick={(e) => {
              e.stopPropagation();
              setSelectedService(row);
              setIsDeleteModalOpen(true);
            }}
          >
            Delete
          </Button>
        </div>
      ),
    },
  ];

  const filteredRequests = serviceRequests.filter(
    (request) =>
      (statusFilter === 'all' || request.status === statusFilter) &&
      (request.userName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        request.location.toLowerCase().includes(searchTerm.toLowerCase()) ||
        request.contact.includes(searchTerm))
  );

  const paginatedRequests = filteredRequests.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  const totalPages = Math.ceil(filteredRequests.length / pageSize);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-blue-50 to-indigo-50 p-6">
      <ToastContainer toasts={toasts} onRemove={removeToast} />
      <div className="max-w-7xl mx-auto space-y-8">
        <motion.div
          {...pageAnimations.header}
          className="bg-white rounded-2xl shadow-xl border border-gray-100 p-8"
        >
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
            <div className="flex items-center">
              <div className="p-3 bg-gradient-to-r from-blue-500 to-indigo-600 rounded-xl mr-4">
                <TruckIcon size={28} className="text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-blue-900 to-indigo-900 bg-clip-text text-transparent">
                  Booking Management
                </h1>
                <p className="text-gray-600 mt-2 text-lg">
                  Manage and track customer bookings efficiently
                </p>
              </div>
            </div>
          </div>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <motion.div
            {...pageAnimations.statsCard(0)}
            className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-xl transition-all duration-300 hover:-translate-y-1 group"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">
                  Total Bookings
                </p>
                <p className="text-3xl font-bold text-gray-900 mb-2">{serviceRequests.length}</p>
                <div className="flex items-center text-xs text-gray-500">
                  <div className="w-2 h-2 bg-blue-400 rounded-full mr-2"></div>
                  All bookings
                </div>
              </div>
              <div className="p-4 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-110">
                <UserIcon className="h-8 w-8 text-white" />
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-100">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500">Booking Portfolio</span>
                <span className="text-blue-600 font-medium">Active</span>
              </div>
              <div className="mt-2 w-full bg-gray-200 rounded-full h-1.5">
                <div
                  className="bg-gradient-to-r from-blue-500 to-indigo-600 h-1.5 rounded-full transition-all duration-500"
                  style={{ width: '100%' }}
                ></div>
              </div>
            </div>
          </motion.div>
          <motion.div
            {...pageAnimations.statsCard(1)}
            className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-xl transition-all duration-300 hover:-translate-y-1 group"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">
                  Pending
                </p>
                <p className="text-3xl font-bold text-yellow-600 mb-2">
                  {serviceRequests.filter((r) => r.status === 'Pending').length}
                </p>
                <div className="flex items-center text-xs text-gray-500">
                  <div className="w-2 h-2 bg-yellow-400 rounded-full mr-2"></div>
                  Awaiting action
                </div>
              </div>
              <div className="p-4 bg-gradient-to-br from-yellow-400 to-orange-500 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-110">
                <AlertCircleIcon className="h-8 w-8 text-white" />
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-100">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500">Pending Rate</span>
                <span className="text-yellow-600 font-medium">
                  {serviceRequests.length > 0
                    ? Math.round(
                        (serviceRequests.filter((r) => r.status === 'Pending').length /
                          serviceRequests.length) *
                          100
                      )
                    : 0}
                  %
                </span>
              </div>
              <div className="mt-2 w-full bg-gray-200 rounded-full h-1.5">
                <div
                  className="bg-gradient-to-r from-yellow-400 to-orange-500 h-1.5 rounded-full transition-all duration-500"
                  style={{
                    width: `${
                      serviceRequests.length > 0
                        ? Math.round(
                            (serviceRequests.filter((r) => r.status === 'Pending').length /
                              serviceRequests.length) *
                              100
                          )
                        : 0
                    }%`,
                  }}
                ></div>
              </div>
            </div>
          </motion.div>
          <motion.div
            {...pageAnimations.statsCard(2)}
            className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-xl transition-all duration-300 hover:-translate-y-1 group"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">
                  In Progress
                </p>
                <p className="text-3xl font-bold text-blue-600 mb-2">
                  {serviceRequests.filter((r) => r.status === 'In Progress').length}
                </p>
                <div className="flex items-center text-xs text-gray-500">
                  <div className="w-2 h-2 bg-blue-400 rounded-full mr-2"></div>
                  Currently In Progress
                </div>
              </div>
              <div className="p-4 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-110">
                <CheckIcon className="h-8 w-8 text-white" />
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-100">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500">In Progress Rate</span>
                <span className="text-blue-600 font-medium">
                  {serviceRequests.length > 0
                    ? Math.round(
                        (serviceRequests.filter((r) => r.status === 'In Progress').length /
                          serviceRequests.length) *
                          100
                      )
                    : 0}
                  %
                </span>
              </div>
              <div className="mt-2 w-full bg-gray-200 rounded-full h-1.5">
                <div
                  className="bg-gradient-to-r from-indigo-500 to-purple-600 h-1.5 rounded-full transition-all duration-500"
                  style={{
                    width: `${
                      serviceRequests.length > 0
                        ? Math.round(
                            (serviceRequests.filter((r) => r.status === 'In Progress').length /
                              serviceRequests.length) *
                              100
                          )
                        : 0
                    }%`,
                  }}
                ></div>
              </div>
            </div>
          </motion.div>
          <motion.div
            {...pageAnimations.statsCard(3)}
            className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-xl transition-all duration-300 hover:-translate-y-1 group"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">
                  Completed
                </p>
                <p className="text-3xl font-bold text-green-600 mb-2">
                  {serviceRequests.filter((r) => r.status === 'Completed').length}
                </p>
                <div className="flex items-center text-xs text-gray-500">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                  Successfully completed
                </div>
              </div>
              <div className="p-4 bg-gradient-to-br from-green-500 to-emerald-600 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-110">
                <CheckCircleIcon className="h-8 w-8 text-white" />
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-100">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500">Completion Rate</span>
                <span className="text-green-600 font-medium">
                  {serviceRequests.length > 0
                    ? Math.round(
                        (serviceRequests.filter((r) => r.status === 'Completed').length /
                          serviceRequests.length) *
                          100
                      )
                    : 0}
                  %
                </span>
              </div>
              <div className="mt-2 w-full bg-gray-200 rounded-full h-1.5">
                <div
                  className="bg-gradient-to-r from-green-500 to-emerald-600 h-1.5 rounded-full transition-all duration-500"
                  style={{
                    width: `${
                      serviceRequests.length > 0
                        ? Math.round(
                            (serviceRequests.filter((r) => r.status === 'Completed').length /
                              serviceRequests.length) *
                              100
                          )
                        : 0
                    }%`,
                  }}
                ></div>
              </div>
            </div>
          </motion.div>
        </div>

        <motion.div
          {...pageAnimations.mainContent}
          className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden"
        >
          {loading ? (
            <div className="py-16 text-center">
              <div className="flex justify-center mb-4">
                <div className="animate-spin rounded-full h-12 w-12 border-4 border-blue-500 border-t-transparent"></div>
              </div>
              <p className="text-gray-600 text-lg font-medium">Loading bookings...</p>
              <p className="text-gray-400 text-sm mt-1">Please wait while we fetch your data</p>
            </div>
          ) : error ? (
            <div className="py-16 text-center text-red-500">
              <div className="flex justify-center mb-4">
                <div className="p-4 bg-red-100 rounded-full">
                  <XIcon size={32} className="text-red-500" />
                </div>
              </div>
              <p className="text-lg font-medium">{error}</p>
            </div>
          ) : (
            <div className="px-8 pt-6 pb-8">
              <div className="p-6 border-b border-gray-200 bg-gradient-to-r from-gray-50 to-white rounded-xl mb-6">
                <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center space-y-4 lg:space-y-0">
                  <div className="flex-1 max-w-md">
                    <div className="relative">
                      <SearchIcon
                        size={18}
                        className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400"
                      />
                      <input
                        type="text"
                        placeholder="Search bookings by customer name..."
                        className="w-full pl-10 pr-4 py-3 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white shadow-sm hover:border-gray-300 transition-colors duration-200"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-3">
                    <div className="flex items-center space-x-2">
                      <span className="text-sm text-gray-600 font-medium">Filter by Status:</span>
                      <select
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-emerald-500 focus:border-emerald-500 text-gray-700"
                      >
                        <option value="all">All Statuses</option>
                        <option value="Pending">Pending</option>
                        <option value="In Progress">In Progress</option>
                        <option value="Completed">Completed</option>
                        <option value="Canceled">Canceled</option>
                        <option value="Confirmed">Confirmed</option>
                      </select>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-200 bg-gray-50">
                  <h4 className="text-lg font-semibold text-gray-800">Bookings</h4>
                </div>
                <div className="overflow-x-auto">
                  <Table
                    columns={columns}
                    data={paginatedRequests}
                    onRowClick={(row) => {
                      setSelectedService(row);
                      setIsViewModalOpen(true);
                    }}
                  />
                </div>
              </div>

              <div className="flex justify-between items-center mt-6 p-4 bg-gray-50 rounded-lg">
                <p className="text-sm text-gray-600">
                  Showing {paginatedRequests.length} of {filteredRequests.length} bookings
                </p>
                <div className="flex items-center space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage((prev) => Math.max(prev - 1, 1))}
                    disabled={currentPage === 1}
                  >
                    Previous
                  </Button>
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                    <Button
                      key={page}
                      variant={currentPage === page ? 'primary' : 'outline'}
                      size="sm"
                      onClick={() => setCurrentPage(page)}
                    >
                      {page}
                    </Button>
                  ))}
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage((prev) => Math.min(prev + 1, totalPages))}
                    disabled={currentPage === totalPages}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </div>
          )}
        </motion.div>

        <Modal isOpen={isViewModalOpen} onClose={() => setIsViewModalOpen(false)} title="" size="lg">
          {selectedService && (
            <div className="bg-gradient-to-br from-blue-50 to-indigo-50 -m-6 p-8 rounded-t-lg">
              <div className="text-center mb-8">
                <h2 className="text-3xl font-bold text-gray-900 mb-2">Booking Details</h2>
                <div className="flex justify-center">
                  <span
                    className={`px-4 py-2 text-sm font-semibold rounded-full shadow-sm ${
                      selectedService.status === 'Completed'
                        ? 'bg-green-100 text-green-800 border border-green-200'
                        : selectedService.status === 'Pending'
                        ? 'bg-yellow-100 text-yellow-800 border border-yellow-200'
                        : selectedService.status === 'In Progress'
                        ? 'bg-blue-100 text-blue-800 border border-blue-200'
                        : selectedService.status === 'Confirmed'
                        ? 'bg-purple-100 text-purple-800 border border-purple-200'
                        : 'bg-red-100 text-red-800 border border-red-200'
                    }`}
                  >
                    {selectedService.status}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
                <div className="bg-white rounded-2xl shadow-md p-6 border border-gray-100">
                  <div className="flex items-center mb-6">
                    <div className="p-3 bg-blue-100 rounded-xl mr-3">
                      <UserIcon size={24} className="text-blue-600" />
                    </div>
                    <h3 className="text-xl font-bold text-gray-900">Customer Information</h3>
                  </div>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between py-3 border-b border-gray-100">
                      <div className="flex items-center">
                        <UserIcon size={18} className="mr-3 text-gray-400" />
                        <span className="text-sm font-medium text-gray-600">User Name</span>
                      </div>
                      <span className="text-sm font-semibold text-gray-900">{selectedService.userName}</span>
                    </div>
                    <div className="flex items-center justify-between py-3 border-b border-gray-100">
                      <div className="flex items-center">
                        <PhoneIcon size={18} className="mr-3 text-gray-400" />
                        <span className="text-sm font-medium text-gray-600">Contact</span>
                      </div>
                      <span className="text-sm text-gray-900 font-mono">{selectedService.contact}</span>
                    </div>
                    <div className="flex items-center justify-between py-3 border-b border-gray-100">
                      <div className="flex items-center">
                        <MapPinIcon size={18} className="mr-3 text-gray-400" />
                        <span className="text-sm font-medium text-gray-600">Location</span>
                      </div>
                      <span className="text-sm text-gray-900">{selectedService.location}</span>
                    </div>
                    <div className="flex items-center justify-between py-3">
                      <div className="flex items-center">
                        <CalendarIcon size={18} className="mr-3 text-gray-400" />
                        <span className="text-sm font-medium text-gray-600">Booking Date</span>
                      </div>
                      <span className="text-sm text-gray-900">
                        {selectedService.date ? new Date(selectedService.date).toLocaleDateString() : 'N/A'}
                      </span>
                    </div>
                  </div>

                  <div className="bg-white rounded-2xl shadow-md p-6 border border-gray-100">
                    <h3 className="text-lg font-bold text-gray-900 mb-4">Financial Summary</h3>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between p-4 bg-gray-50 rounded-xl">
                        <div className="flex items-center">
                          <DollarSignIcon size={18} className="mr-3 text-gray-400" />
                          <span className="text-sm font-medium text-gray-600">Total Price</span>
                        </div>
                        <span className="text-lg font-bold text-gray-900">
                          LKR {selectedService.price.toLocaleString()}
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-4 bg-blue-50 rounded-xl">
                        <div className="flex items-center">
                          <DollarSignIcon size={18} className="mr-3 text-blue-400" />
                          <span className="text-sm font-medium text-blue-600">Advance Payment</span>
                        </div>
                        <span className="text-lg font-bold text-blue-700">
                          LKR {selectedService.advance.toLocaleString()}
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-4 bg-red-50 rounded-xl">
                        <div className="flex items-center">
                          <DollarSignIcon size={18} className="mr-3 text-red-400" />
                          <span className="text-sm font-medium text-red-600">Remaining Balance</span>
                        </div>
                        <span className="text-lg font-bold text-red-700">
                          LKR {selectedService.balance.toLocaleString()}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white rounded-2xl shadow-md p-6 border border-gray-100 mb-8">
                <h3 className="text-lg font-bold text-gray-900 mb-4">Assigned Employees</h3>
                <div className="flex flex-wrap gap-3">
                  {assignedEmployees.length > 0 ? (
                    assignedEmployees.map((employee) => (
                      <div
                        key={employee.id}
                        className="flex items-center bg-green-50 text-green-700 px-4 py-3 rounded-xl border border-green-200 shadow-sm"
                      >
                        <UserIcon size={16} className="mr-3 flex-shrink-0" />
                        <div className="flex flex-col">
                          <span className="font-semibold text-sm">{employee.fullName}</span>
                          <span className="text-xs text-green-600">{employee.position || 'Employee'}</span>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 w-full">
                      <UserIcon size={32} className="text-gray-300 mx-auto mb-2" />
                      <p className="text-gray-500">No employees assigned to this booking</p>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
                <Button
                  variant="outline"
                  onClick={() => setIsViewModalOpen(false)}
                  className="px-6 py-2.5 text-gray-700 border-gray-300 hover:bg-gray-50 shadow-sm"
                >
                  Close
                </Button>
                <Button
                  variant="primary"
                  onClick={() => {
                    setIsViewModalOpen(false);
                    setIsEditModalOpen(true);
                  }}
                  className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white shadow-sm"
                  icon={<EditIcon size={16} />}
                >
                  Edit Booking
                </Button>
              </div>
            </div>
          )}
        </Modal>

        <Modal
          isOpen={isEditModalOpen}
          onClose={() => setIsEditModalOpen(false)}
          title="Edit Booking"
          size="lg"
        >
          {selectedService && (
            <form
              className="space-y-6"
              onSubmit={async (e) => {
                e.preventDefault();
                setLoading(true);
                setError(null);
                try {
                  const token = localStorage.getItem('authToken');
                  if (!token) throw new Error('No authentication token available');
                  const baseUrl = import.meta.env.VITE_API_BASE_URL;
                  const response = await fetch(`${baseUrl}/api/personnel/update-booking`, {
                    method: 'PUT',
                    headers: {
                      Authorization: `Bearer ${token}`,
                      'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                      serviceBookData: {
                        _id: selectedService.id,
                        userName: editFormData.userName,
                        contact: editFormData.contact,
                        location: editFormData.location,
                        date: editFormData.date,
                        staff: selectedStaff,
                        advance: currentAdvance,
                        price: editFormData.price,
                        balance: currentBalance,
                        status: editFormData.status,
                      },
                    }),
                  });
                  const data = await response.json();
                  if (data.success) {
                    const fetchResponse = await fetch(`${baseUrl}/api/personnel/getall-bookings`, {
                      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                    });
                    const newData = await fetchResponse.json();
                    if (newData.success && Array.isArray(newData.allBookings)) {
                      setServiceRequests(
                        newData.allBookings.map((req: any) => ({
                          id: req._id,
                          userName: req.userName,
                          contact: req.contact,
                          location: req.location,
                          imageUrl: req.imageUrl || '',
                          date: req.date ? req.date.slice(0, 10) : '',
                          advance: req.advance || 0,
                          price: req.price || 0,
                          balance: req.balance || (req.price && req.advance ? req.price - req.advance : 0),
                          status: req.status,
                          staff: req.staff || [],
                        }))
                      );
                    }
                    setIsEditModalOpen(false);
                    addToast('success', 'Booking Updated', data.message || 'Booking has been updated successfully');
                  } else {
                    addToast('error', 'Update Failed', data.message || 'Failed to update booking');
                  }
                } catch (err: any) {
                  addToast('error', 'Update Failed', err.message || 'Failed to update booking');
                } finally {
                  setLoading(false);
                }
              }}
            >
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label htmlFor="edit-userName" className="block text-sm font-semibold text-gray-700 mb-2">
                    User Name
                  </label>
                  <input
                    type="text"
                    id="edit-userName"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-gray-50"
                    value={editFormData.userName}
                    onChange={(e) => setEditFormData((prev) => ({ ...prev, userName: e.target.value }))}
                  />
                </div>
                <div>
                  <label htmlFor="edit-contact" className="block text-sm font-semibold text-gray-700 mb-2">
                    Contact
                  </label>
                  <input
                    type="text"
                    id="edit-contact"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-gray-50"
                    value={editFormData.contact}
                    onChange={(e) => setEditFormData((prev) => ({ ...prev, contact: e.target.value }))}
                  />
                </div>
                <div>
                  <label htmlFor="edit-location" className="block text-sm font-semibold text-gray-700 mb-2">
                    Location
                  </label>
                  <input
                    type="text"
                    id="edit-location"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-gray-50"
                    value={editFormData.location}
                    onChange={(e) => setEditFormData((prev) => ({ ...prev, location: e.target.value }))}
                  />
                </div>
                <div>
                  <label htmlFor="edit-date" className="block text-sm font-semibold text-gray-700 mb-2">
                    Booking Date
                  </label>
                  <input
                    type="date"
                    id="edit-date"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-gray-50"
                    value={editFormData.date}
                    onChange={(e) => setEditFormData((prev) => ({ ...prev, date: e.target.value }))}
                  />
                </div>
                <div>
                  <label htmlFor="edit-status" className="block text-sm font-semibold text-gray-700 mb-2">
                    Status
                  </label>
                  <select
                    id="edit-status"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    value={editFormData.status}
                    onChange={(e) => setEditFormData((prev) => ({ ...prev, status: e.target.value as PickupRequest['status'] }))}
                  >
                    <option value="Pending">Pending</option>
                    <option value="In Progress">In Progress</option>
                    <option value="Completed">Completed</option>
                    <option value="Canceled">Canceled</option>
                    <option value="Confirmed">Confirmed</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="edit-price" className="block text-sm font-semibold text-gray-700 mb-2">
                    Price (LKR)
                  </label>
                  <input
                    type="number"
                    id="edit-price"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    value={editFormData.price}
                    onChange={(e) => setEditFormData((prev) => ({ ...prev, price: Number(e.target.value) || 0 }))}
                    min={0}
                  />
                </div>
                <div>
                  <label htmlFor="edit-advance-percent" className="block text-sm font-semibold text-gray-700 mb-2">
                    Advance Percentage (%)
                  </label>
                  <input
                    type="number"
                    id="edit-advance-percent"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    value={editFormData.advancePercentage}
                    onChange={(e) => setEditFormData((prev) => ({ ...prev, advancePercentage: Number(e.target.value) || 0 }))}
                    min={0}
                    max={100}
                  />
                </div>
                <div>
                  <label htmlFor="edit-advance" className="block text-sm font-semibold text-gray-700 mb-2">
                    Advance Payment (LKR)
                  </label>
                  <input
                    type="number"
                    id="edit-advance"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl bg-gray-50 text-gray-600"
                    value={currentAdvance}
                    disabled
                    readOnly
                  />
                </div>
                <div>
                  <label htmlFor="edit-balance" className="block text-sm font-semibold text-gray-700 mb-2">
                    Balance (LKR) {editFormData.advancePercentage > 0 ? '- Auto Calculated' : ''}
                  </label>
                  <input
                    type="number"
                    id="edit-balance"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl bg-gray-50 text-gray-600 cursor-not-allowed"
                    value={currentBalance}
                    disabled
                    readOnly
                    placeholder={editFormData.advancePercentage > 0 ? 'Auto-calculated' : `DB Value: ${selectedService?.balance || 0}`}
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    {editFormData.advancePercentage > 0
                      ? `Auto-calculated from ${editFormData.advancePercentage}% advance`
                      : `View only - cannot be edited`}
                  </p>
                </div>
                {/* Removed weight, recyclables, and notes fields as requested */}
                <div className="col-span-1 md:col-span-2">
                  <label className="block text-sm font-semibold text-gray-700 mb-3">Assign Employees</label>
                  <div className="bg-gray-50 rounded-xl border border-gray-200 p-4">
                    <div className="mb-2 flex flex-wrap gap-2">
                      {selectedStaff.length === 0 && (
                        <span className="text-xs text-gray-400">No employees assigned yet</span>
                      )}
                      {selectedStaff.map((id) => {
                        const emp = employees.find((e) => e.id === id);
                        if (!emp) return null;
                        return (
                          <span key={id} className="inline-flex items-center bg-green-50 text-green-700 px-3 py-1 rounded-full border border-green-200 shadow-sm text-xs font-medium mr-2 mb-2">
                            <UserIcon size={14} className="mr-1" />
                            {emp.fullName}
                            <button type="button" className="ml-2 text-red-400 hover:text-red-600" onClick={() => setSelectedStaff(selectedStaff.filter((sid) => sid !== id))}>
                              <XIcon size={12} />
                            </button>
                          </span>
                        );
                      })}
                    </div>
                    <div className="flex flex-col gap-2">
                      <input
                        type="text"
                        placeholder="Search employees..."
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent mb-2"
                        onChange={e => {
                          const val = e.target.value.toLowerCase();
                          setEmployees(prev => prev.map(emp => ({ ...emp, _filtered: emp.fullName.toLowerCase().includes(val) })));
                        }}
                      />
                      <div className="max-h-32 overflow-y-auto flex flex-wrap gap-2">
                        {employees.filter(emp => !selectedStaff.includes(emp.id)).map(emp => (
                          <button
                            key={emp.id}
                            type="button"
                            className="inline-flex items-center bg-white hover:bg-blue-50 text-gray-700 px-3 py-1 rounded-full border border-gray-200 shadow-sm text-xs font-medium mr-2 mb-2 transition-all duration-150"
                            onClick={() => setSelectedStaff([...selectedStaff, emp.id])}
                          >
                            <UserIcon size={14} className="mr-1" />
                            {emp.fullName}
                            {emp.position && <span className="ml-2 text-gray-400">({emp.position})</span>}
                          </button>
                        ))}
                        {employees.filter(emp => !selectedStaff.includes(emp.id)).length === 0 && (
                          <span className="text-xs text-gray-400">No more employees to assign</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
                <Button
                  variant="outline"
                  type="button"
                  onClick={() => {
                    setIsEditModalOpen(false);
                  }}
                  className="px-6 py-2.5 shadow-sm"
                >
                  Cancel
                </Button>
                <Button type="submit" variant="primary" className="px-6 py-2.5 shadow-sm">
                  Update Booking
                </Button>
              </div>
            </form>
          )}
        </Modal>

        <Modal
          isOpen={isDeleteModalOpen}
          onClose={() => setIsDeleteModalOpen(false)}
          title="Delete Booking"
        >
          {selectedService && (
            <div className="text-center">
              <div className="p-4 bg-red-100 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                <TrashIcon size={32} className="text-red-500" />
              </div>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">Delete Booking</h3>
              <p className="text-gray-600 mb-6">
                Are you sure you want to delete the booking for{' '}
                <span className="font-semibold text-gray-900">{selectedService.userName}</span>? This
                action cannot be undone and all associated data will be permanently removed.
              </p>
              <div className="bg-gray-50 rounded-xl p-4 mb-6">
                <div className="text-sm text-gray-600 space-y-1">
                  <p>
                    <span className="font-medium">Customer:</span> {selectedService.userName}
                  </p>
                  <p>
                    <span className="font-medium">Location:</span> {selectedService.location}
                  </p>
                  <p>
                    <span className="font-medium">Date:</span>{' '}
                    {selectedService.date ? new Date(selectedService.date).toLocaleDateString() : 'N/A'}
                  </p>
                  <p>
                    <span className="font-medium">Status:</span> {selectedService.status}
                  </p>
                </div>
              </div>
              <div className="flex justify-center space-x-4">
                <Button
                  variant="outline"
                  onClick={() => setIsDeleteModalOpen(false)}
                  className="px-6 py-2.5 shadow-sm"
                >
                  Cancel
                </Button>
                <Button
                  variant="danger"
                  onClick={async () => {
                    setLoading(true);
                    try {
                      const token = localStorage.getItem('authToken');
                      if (!token) throw new Error('No authentication token available');
                      const baseUrl = import.meta.env.VITE_API_BASE_URL;
                      const response = await fetch(
                        `${baseUrl}/api/personnel/delete-booking/${selectedService.id}`,
                        {
                          method: 'DELETE',
                          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                        }
                      );
                      const data = await response.json();
                      if (data.success) {
                        const fetchResponse = await fetch(`${baseUrl}/api/personnel/getall-bookings`, {
                          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                        });
                        const newData = await fetchResponse.json();
                        if (newData.success && Array.isArray(newData.allBookings)) {
                          setServiceRequests(
                            newData.allBookings.map((req: any) => ({
                              id: req._id,
                              userName: req.userName,
                              contact: req.contact,
                              location: req.location,
                              imageUrl: req.imageUrl || '',
                              date: req.date ? req.date.slice(0, 10) : '',
                              advance: req.advance || 0,
                              price: req.price || 0,
                              balance: req.balance || (req.price && req.advance ? req.price - req.advance : 0),
                              status: req.status,
                              staff: req.staff || [],
                            }))
                          );
                        }
                        setIsDeleteModalOpen(false);
                        addToast('success', 'Booking Deleted', data.message || 'Booking has been deleted successfully');
                      } else {
                        addToast('error', 'Delete Failed', data.message || 'Failed to delete booking');
                      }
                    } catch (err: any) {
                      addToast('error', 'Delete Failed', err.message || 'Failed to delete booking');
                    } finally {
                      setLoading(false);
                    }
                  }}
                  className="px-6 py-2.5 shadow-sm"
                >
                  Delete Booking
                </Button>
              </div>
            </div>
          )}
        </Modal>
      </div>
    </div>
  );
};

export default PickupRequestManager;