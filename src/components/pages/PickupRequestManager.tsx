import { useState, useEffect } from 'react';
import { SearchIcon, EditIcon, TrashIcon, CheckIcon, XIcon, ImageIcon, MapPinIcon, PhoneIcon, DollarSignIcon, UserIcon, CheckCircleIcon, XCircleIcon, AlertCircleIcon, TruckIcon } from 'lucide-react';
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

const PickupRequestManager = () => {
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState<any>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [pickupRequests, setPickupRequests] = useState<any[]>([]);
  const [editStatus, setEditStatus] = useState<string>('Pending');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editAdvancePercent, setEditAdvancePercent] = useState<number>(0);
  const [editPrice, setEditPrice] = useState<number>(0); // Fixed typo: changed itPrice to editPrice
  const [editAdvance, setEditAdvance] = useState<number>(0);
  const [editBalance, setEditBalance] = useState<number>(0);
  const [editAssignedStaff, setEditAssignedStaff] = useState<string[]>([]);
  const [employees, setEmployees] = useState<any[]>([]);
  const [assignedEmployeeDetails, setAssignedEmployeeDetails] = useState<any[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);

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

  useEffect(() => {
    const fetchPickupRequests = async () => {
      setLoading(true);
      setError(null);
      try {
        const token = localStorage.getItem('authToken');
        const baseUrl = import.meta.env.VITE_API_BASE_URL;
        const response = await fetch(`${baseUrl}/api/personnel/get-all-request`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await response.json();
        if (data.success && Array.isArray(data.allPickups)) {
          setPickupRequests(
            data.allPickups.map((req: any) => ({
              id: req._id,
              username: req.userName,
              contact: req.contact,
              location: req.location,
              imageURL: req.imageUrl,
              date: req.date ? req.date.slice(0, 10) : '',
              advance: req.advance,
              price: req.price,
              balance: req.balance,
              status: req.status,
              staff: req.staff || [],
            }))
          );
        } else {
          setPickupRequests([]);
          addToast('warning', 'No Data', 'No pickup requests found');
        }
      } catch (err: any) {
        addToast('error', 'Loading Failed', 'Failed to fetch pickup requests');
      } finally {
        setLoading(false);
      }
    };
    fetchPickupRequests();
  }, []);

  useEffect(() => {
    const fetchEmployees = async () => {
      try {
        const token = localStorage.getItem('authToken');
        const baseUrl = import.meta.env.VITE_API_BASE_URL;
        const response = await fetch(`${baseUrl}/api/personnel/all-employees`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await response.json();
        if (data.success && Array.isArray(data.data)) {
          setEmployees(data.data);
        } else {
          setEmployees([]);
          addToast('warning', 'No Employees', 'No employees available for assignment');
        }
      } catch (err) {
        setEmployees([]);
        addToast('error', 'Loading Failed', 'Failed to fetch employees');
      }
    };
    fetchEmployees();
  }, []);

  useEffect(() => {
    if (selectedRequest && isEditModalOpen) {
      setEditStatus(selectedRequest.status);
      setEditPrice(selectedRequest.price);
      const percent = selectedRequest.price ? Math.round((selectedRequest.advance / selectedRequest.price) * 100) : 0;
      setEditAdvancePercent(percent);
      setEditAdvance(selectedRequest.advance);
      setEditBalance(selectedRequest.balance);
      setEditAssignedStaff(selectedRequest.staff || []);
    }
  }, [selectedRequest, isEditModalOpen]);

  useEffect(() => {
    const adv = Math.round((editPrice * editAdvancePercent) / 100);
    setEditAdvance(adv);
    setEditBalance(editPrice - adv);
  }, [editPrice, editAdvancePercent]);

  useEffect(() => {
    const fetchAssignedEmployees = async () => {
      if (selectedRequest && isViewModalOpen && selectedRequest.staff && selectedRequest.staff.length > 0) {
        try {
          const token = localStorage.getItem('authToken');
          const baseUrl = import.meta.env.VITE_API_BASE_URL;
          const details = await Promise.all(
            selectedRequest.staff.map(async (id: string) => {
              const res = await fetch(`${baseUrl}/api/personnel/get-employee/${id}`, {
                headers: { Authorization: `Bearer ${token}` },
              });
              const data = await res.json();
              return data.success ? data.data : null;
            })
          );
          setAssignedEmployeeDetails(details.filter(Boolean));
        } catch (err) {
          console.error('Error fetching assigned employee details:', err);
          setAssignedEmployeeDetails([]);
          addToast('error', 'Loading Failed', 'Failed to fetch assigned employee details');
        }
      } else {
        setAssignedEmployeeDetails([]);
      }
    };
    fetchAssignedEmployees();
  }, [selectedRequest, isViewModalOpen]);

  const columns = [
    {
      header: 'Username',
      accessor: 'username',
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
      header: 'Balance',
      accessor: 'balance',
      cell: (value: number) => (
        <div className="flex items-center">
          <DollarSignIcon size={16} className="mr-1 text-gray-400" />
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
      cell: (_: any, row: any) => (
        <div className="flex space-x-2">
          <Button
            variant="outline"
            size="sm"
            icon={<EditIcon size={14} />}
            onClick={(e) => {
              e.stopPropagation();
              setSelectedRequest(row);
              setIsEditModalOpen(true);
            }}
          >
            Edit
          </Button>
          <Button
            variant="outline"
            size="sm"
            icon={<CheckIcon size={14} />}
            onClick={(e) => {
              e.stopPropagation();
              setSelectedRequest(row);
              setIsViewModalOpen(true);
            }}
          >
            View
          </Button>
          <Button
            variant="danger"
            size="sm"
            icon={<TrashIcon size={14} />}
            onClick={(e) => {
              e.stopPropagation();
              setSelectedRequest(row);
              setIsDeleteModalOpen(true);
            }}
          >
            Delete
          </Button>
        </div>
      ),
    },
  ];

  const filteredRequests = pickupRequests.filter(
    (request) =>
      (statusFilter === 'all' || request.status.toLowerCase() === statusFilter.toLowerCase()) &&
      (request.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
        request.location.toLowerCase().includes(searchTerm.toLowerCase()) ||
        request.contact.includes(searchTerm))
  );

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
                  Pickup Request Management
                </h1>
                <p className="text-gray-600 mt-2 text-lg">
                  Manage and track customer pickup requests efficiently
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
                  Total Requests
                </p>
                <p className="text-3xl font-bold text-gray-900 mb-2">{pickupRequests.length}</p>
                <div className="flex items-center text-xs text-gray-500">
                  <div className="w-2 h-2 bg-blue-400 rounded-full mr-2"></div>
                  All pickup requests
                </div>
              </div>
              <div className="p-4 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-110">
                <UserIcon className="h-8 w-8 text-white" />
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-100">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500">Request Portfolio</span>
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
                  {pickupRequests.filter((r) => r.status === 'Pending').length}
                </p>
                <div className="flex items-center text-xs text-gray-500">
                  <div className="w-2 h-2 bg-yellow-400 rounded-full mr-2"></div>
                  Awaiting pickup
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
                  {pickupRequests.length > 0
                    ? Math.round(
                        (pickupRequests.filter((r) => r.status === 'Pending').length /
                          pickupRequests.length) *
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
                      pickupRequests.length > 0
                        ? Math.round(
                            (pickupRequests.filter((r) => r.status === 'Pending').length /
                              pickupRequests.length) *
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
                  {pickupRequests.filter((r) => r.status === 'In Progress').length}
                </p>
                <div className="flex items-center text-xs text-gray-500">
                  <div className="w-2 h-2 bg-blue-400 rounded-full mr-2"></div>
                  Currently processing
                </div>
              </div>
              <div className="p-4 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-110">
                <CheckIcon className="h-8 w-8 text-white" />
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-100">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500">Progress Rate</span>
                <span className="text-blue-600 font-medium">
                  {pickupRequests.length > 0
                    ? Math.round(
                        (pickupRequests.filter((r) => r.status === 'In Progress').length /
                          pickupRequests.length) *
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
                      pickupRequests.length > 0
                        ? Math.round(
                            (pickupRequests.filter((r) => r.status === 'In Progress').length /
                              pickupRequests.length) *
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
                  {pickupRequests.filter((r) => r.status === 'Completed').length}
                </p>
                <div className="flex items-center text-xs text-gray-500">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                  Successfully picked up
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
                  {pickupRequests.length > 0
                    ? Math.round(
                        (pickupRequests.filter((r) => r.status === 'Completed').length /
                          pickupRequests.length) *
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
                      pickupRequests.length > 0
                        ? Math.round(
                            (pickupRequests.filter((r) => r.status === 'Completed').length /
                              pickupRequests.length) *
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
              <p className="text-gray-600 text-lg font-medium">Loading pickup requests...</p>
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
                        placeholder="Search pickup requests by customer name..."
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
                        className="admin-dropdown admin-dropdown-primary"
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
                  <h4 className="text-lg font-semibold text-gray-800">Pickup Requests</h4>
                </div>
                <div className="overflow-x-auto">
                  <Table
                    columns={columns}
                    data={filteredRequests}
                    onRowClick={(row) => {
                      setSelectedRequest(row);
                      setIsViewModalOpen(true);
                    }}
                  />
                </div>
              </div>

              <div className="flex justify-between items-center mt-6 p-4 bg-gray-50 rounded-lg">
                <p className="text-sm text-gray-600">
                  Showing {filteredRequests.length} of {pickupRequests.length} pickup requests
                </p>
                <div className="flex items-center space-x-2">
                  <Button variant="outline" size="sm">
                    Previous
                  </Button>
                  <Button variant="outline" size="sm" className="bg-blue-50 border-blue-400 text-blue-700">
                    1
                  </Button>
                  <Button variant="outline" size="sm">
                    2
                  </Button>
                  <Button variant="outline" size="sm">
                    Next
                  </Button>
                </div>
              </div>
            </div>
          )}
        </motion.div>

        <Modal isOpen={isViewModalOpen} onClose={() => setIsViewModalOpen(false)} title="" size="lg">
          {selectedRequest && (
            <div className="bg-gradient-to-br from-blue-50 to-indigo-50 -m-6 p-8 rounded-t-lg">
              <div className="text-center mb-8">
                <h2 className="text-3xl font-bold text-gray-900 mb-2">Pickup Request Details</h2>
                <div className="flex justify-center">
                  <span
                    className={`px-4 py-2 text-sm font-semibold rounded-full shadow-sm ${
                      selectedRequest.status === 'Completed'
                        ? 'bg-green-100 text-green-800 border border-green-200'
                        : selectedRequest.status === 'Pending'
                        ? 'bg-yellow-100 text-yellow-800 border border-yellow-200'
                        : selectedRequest.status === 'In Progress'
                        ? 'bg-blue-100 text-blue-800 border border-blue-200'
                        : selectedRequest.status === 'Confirmed'
                        ? 'bg-purple-100 text-purple-800 border border-purple-200'
                        : 'bg-red-100 text-red-800 border border-red-200'
                    }`}
                  >
                    {selectedRequest.status}
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
                        <span className="text-sm font-medium text-gray-600">Username</span>
                      </div>
                      <span className="text-sm font-semibold text-gray-900">{selectedRequest.username}</span>
                    </div>
                    <div className="flex items-center justify-between py-3 border-b border-gray-100">
                      <div className="flex items-center">
                        <PhoneIcon size={18} className="mr-3 text-gray-400" />
                        <span className="text-sm font-medium text-gray-600">Contact</span>
                      </div>
                      <span className="text-sm text-gray-900 font-mono">{selectedRequest.contact}</span>
                    </div>
                    <div className="flex items-center justify-between py-3 border-b border-gray-100">
                      <div className="flex items-center">
                        <MapPinIcon size={18} className="mr-3 text-gray-400" />
                        <span className="text-sm font-medium text-gray-600">Location</span>
                      </div>
                      <span className="text-sm text-gray-900">{selectedRequest.location}</span>
                    </div>
                    <div className="flex items-center justify-between py-3">
                      <div className="flex items-center">
                        <span className="text-sm font-medium text-gray-600 ml-6">Pickup Date</span>
                      </div>
                      <span className="text-sm text-gray-900">{selectedRequest.date}</span>
                    </div>
                  </div>
                </div>

                <div className="space-y-6">
                  <div className="bg-white rounded-2xl shadow-md p-6 border border-gray-100">
                    <h3 className="text-lg font-bold text-gray-900 mb-4">Pickup Location Image</h3>
                    {selectedRequest.imageURL ? (
                      <img
                        src={selectedRequest.imageURL}
                        alt="Pickup location"
                        className="w-full h-48 object-cover rounded-xl border border-gray-200 shadow-sm"
                      />
                    ) : (
                      <div className="w-full h-48 bg-gradient-to-br from-gray-100 to-gray-200 rounded-xl flex items-center justify-center border border-gray-200">
                        <div className="text-center">
                          <ImageIcon size={48} className="text-gray-400 mx-auto mb-2" />
                          <p className="text-gray-500 text-sm">No image available</p>
                        </div>
                      </div>
                    )}
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
                          LKR {selectedRequest.price.toLocaleString()}
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-4 bg-blue-50 rounded-xl">
                        <div className="flex items-center">
                          <DollarSignIcon size={18} className="mr-3 text-blue-400" />
                          <span className="text-sm font-medium text-blue-600">Advance Payment</span>
                        </div>
                        <span className="text-lg font-bold text-blue-700">
                          LKR {selectedRequest.advance.toLocaleString()}
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-4 bg-red-50 rounded-xl">
                        <div className="flex items-center">
                          <DollarSignIcon size={18} className="mr-3 text-red-400" />
                          <span className="text-sm font-medium text-red-600">Remaining Balance</span>
                        </div>
                        <span className="text-lg font-bold text-red-700">
                          LKR {selectedRequest.balance.toLocaleString()}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white rounded-2xl shadow-md p-6 border border-gray-100 mb-8">
                <h3 className="text-lg font-bold text-gray-900 mb-4">Assigned Employees</h3>
                <div className="flex flex-wrap gap-3">
                  {assignedEmployeeDetails.length > 0 ? (
                    assignedEmployeeDetails.map((emp: any) => (
                      <div
                        key={emp._id}
                        className="flex items-center bg-green-50 text-green-700 px-4 py-3 rounded-xl border border-green-200 shadow-sm"
                      >
                        <UserIcon size={16} className="mr-3 flex-shrink-0" />
                        <div className="flex flex-col">
                          <span className="font-semibold text-sm">{emp.fullName}</span>
                          <span className="text-xs text-green-600">{emp.position || 'Employee'}</span>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 w-full">
                      <UserIcon size={32} className="text-gray-300 mx-auto mb-2" />
                      <p className="text-gray-500">No employees assigned to this pickup request</p>
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
                  Edit Request
                </Button>
              </div>
            </div>
          )}
        </Modal>

        <Modal
          isOpen={isEditModalOpen}
          onClose={() => setIsEditModalOpen(false)}
          title="Edit Pickup Request"
          size="lg"
        >
          {selectedRequest && (
            <form
              className="space-y-6"
              onSubmit={async (e) => {
                e.preventDefault();
                setLoading(true);
                setError(null);
                try {
                  const token = localStorage.getItem('authToken');
                  const baseUrl = import.meta.env.VITE_API_BASE_URL;
                  const formData = new FormData();
                  formData.append(
                    'requestPickupData',
                    JSON.stringify({
                      userName: selectedRequest.username,
                      contact: selectedRequest.contact,
                      location: selectedRequest.location,
                      date: selectedRequest.date,
                      staff: editAssignedStaff,
                      advance: editAdvance,
                      price: editPrice,
                      balance: editBalance,
                      status: editStatus,
                    })
                  );
                  const res = await fetch(
                    `${baseUrl}/api/personnel/update-request/${selectedRequest.id}`,
                    {
                      method: 'PATCH',
                      headers: {
                        Authorization: `Bearer ${token}`,
                      },
                      body: formData,
                    }
                  );
                  const data = await res.json();
                  if (data.success) {
                    const response = await fetch(
                      `${baseUrl}/api/personnel/get-all-request`,
                      {
                        headers: { Authorization: `Bearer ${token}` },
                      }
                    );
                    const newData = await response.json();
                    if (newData.success && Array.isArray(newData.allPickups)) {
                      setPickupRequests(
                        newData.allPickups.map((req: any) => ({
                          id: req._id,
                          username: req.userName,
                          contact: req.contact,
                          location: req.location,
                          imageURL: req.imageUrl,
                          date: req.date ? req.date.slice(0, 10) : '',
                          advance: req.advance,
                          price: req.price,
                          balance: req.balance,
                          status: req.status,
                          staff: req.staff || [],
                        }))
                      );
                    }
                    setIsEditModalOpen(false);
                    addToast('success', 'Request Updated', 'Pickup request has been updated successfully');
                  } else {
                    addToast('error', 'Update Failed', 'Failed to update pickup request');
                  }
                } catch (err: any) {
                  addToast('error', 'Update Failed', 'Failed to update pickup request');
                } finally {
                  setLoading(false);
                }
              }}
            >
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label
                    htmlFor="edit-username"
                    className="block text-sm font-semibold text-gray-700 mb-2"
                  >
                    Username
                  </label>
                  <input
                    type="text"
                    id="edit-username"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-gray-50"
                    value={selectedRequest.username}
                    disabled
                  />
                </div>
                <div>
                  <label
                    htmlFor="edit-contact"
                    className="block text-sm font-semibold text-gray-700 mb-2"
                  >
                    Contact
                  </label>
                  <input
                    type="text"
                    id="edit-contact"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-gray-50"
                    value={selectedRequest.contact}
                    disabled
                  />
                </div>
                <div>
                  <label
                    htmlFor="edit-location"
                    className="block text-sm font-semibold text-gray-700 mb-2"
                  >
                    Location
                  </label>
                  <input
                    type="text"
                    id="edit-location"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-gray-50"
                    value={selectedRequest.location}
                    disabled
                  />
                </div>
                <div>
                  <label
                    htmlFor="edit-date"
                    className="block text-sm font-semibold text-gray-700 mb-2"
                  >
                    Pickup Date
                  </label>
                  <input
                    type="date"
                    id="edit-date"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-gray-50"
                    value={selectedRequest.date}
                    disabled
                  />
                </div>
                <div>
                  <label
                    htmlFor="edit-status"
                    className="block text-sm font-semibold text-gray-700 mb-2"
                  >
                    Status
                  </label>
                  <select
                    id="edit-status"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    value={editStatus}
                    onChange={(e) => setEditStatus(e.target.value)}
                  >
                    <option value="Pending">Pending</option>
                    <option value="In Progress">In Progress</option>
                    <option value="Completed">Completed</option>
                    <option value="Canceled">Canceled</option>
                    <option value="Confirmed">Confirmed</option>
                  </select>
                </div>
                <div>
                  <label
                    htmlFor="edit-price"
                    className="block text-sm font-semibold text-gray-700 mb-2"
                  >
                    Price (LKR)
                  </label>
                  <input
                    type="number"
                    id="edit-price"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    value={editPrice}
                    onChange={(e) => setEditPrice(Number(e.target.value))}
                    min={0}
                  />
                </div>
                <div>
                  <label
                    htmlFor="edit-advance-percent"
                    className="block text-sm font-semibold text-gray-700 mb-2"
                  >
                    Advance Percentage (%)
                  </label>
                  <input
                    type="number"
                    id="edit-advance-percent"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    value={editAdvancePercent}
                    onChange={(e) => setEditAdvancePercent(Number(e.target.value))}
                    min={0}
                    max={100}
                  />
                </div>
                <div>
                  <label
                    htmlFor="edit-advance"
                    className="block text-sm font-semibold text-gray-700 mb-2"
                  >
                    Advance Payment (LKR)
                  </label>
                  <input
                    type="number"
                    id="edit-advance"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-gray-50"
                    value={editAdvance}
                    disabled
                  />
                </div>
                <div>
                  <label
                    htmlFor="edit-balance"
                    className="block text-sm font-semibold text-gray-700 mb-2"
                  >
                    Balance (LKR)
                  </label>
                  <input
                    type="number"
                    id="edit-balance"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-gray-50"
                    value={editBalance}
                    disabled
                  />
                </div>
                <div className="col-span-1 md:col-span-2">
                  <label className="block text-sm font-semibold text-gray-700 mb-3">
                    Assign Employees
                  </label>
                  <div className="mb-4">
                    <div className="flex flex-wrap gap-2 mb-3">
                      {editAssignedStaff.length > 0 ? (
                        editAssignedStaff.map((staffId) => {
                          const employee = employees.find((emp) => emp._id === staffId);
                          return employee ? (
                            <div
                              key={staffId}
                              className="inline-flex items-center bg-blue-100 text-blue-800 px-4 py-2 rounded-full text-sm font-medium border border-blue-200"
                            >
                              <UserIcon size={14} className="mr-2 flex-shrink-0" />
                              <div className="flex flex-col items-start">
                                <span className="font-semibold">{employee.fullName}</span>
                                <span className="text-xs text-blue-600">
                                  {employee.position || 'Employee'}
                                </span>
                              </div>
                              <button
                                type="button"
                                onClick={() =>
                                  setEditAssignedStaff((prev) => prev.filter((id) => id !== staffId))
                                }
                                className="ml-3 text-blue-600 hover:text-blue-800 focus:outline-none flex-shrink-0"
                              >
                                <XIcon size={14} />
                              </button>
                            </div>
                          ) : null;
                        })
                      ) : (
                        <div className="text-sm text-gray-500 py-2 px-3 bg-gray-50 rounded-lg border border-gray-200">
                          No employees assigned yet
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="border border-gray-300 rounded-xl max-h-48 overflow-y-auto bg-white">
                    <div className="p-3 border-b border-gray-200 bg-gray-50 rounded-t-xl">
                      <h4 className="text-sm font-medium text-gray-700">Available Employees</h4>
                    </div>
                    <div className="p-2 space-y-1">
                      {employees.length > 0 ? (
                        employees.map((employee) => {
                          const isSelected = editAssignedStaff.includes(employee._id);
                          return (
                            <div
                              key={employee._id}
                              className={`flex items-center justify-between p-3 rounded-lg cursor-pointer transition-colors ${
                                isSelected
                                  ? 'bg-blue-50 border border-blue-200'
                                  : 'hover:bg-gray-50 border border-transparent'
                              }`}
                              onClick={() => {
                                if (isSelected) {
                                  setEditAssignedStaff((prev) =>
                                    prev.filter((id) => id !== employee._id)
                                  );
                                } else {
                                  setEditAssignedStaff((prev) => [...prev, employee._id]);
                                }
                              }}
                            >
                              <div className="flex items-center">
                                <div
                                  className={`w-4 h-4 rounded border-2 mr-3 flex items-center justify-center ${
                                    isSelected ? 'bg-blue-500 border-blue-500' : 'border-gray-300'
                                  }`}
                                >
                                  {isSelected && <CheckIcon size={12} className="text-white" />}
                                </div>
                                <UserIcon size={16} className="mr-3 text-gray-400 flex-shrink-0" />
                                <div className="flex-1">
                                  <p className="text-sm font-medium text-gray-900 leading-tight">
                                    {employee.fullName}
                                  </p>
                                  <p className="text-xs text-gray-500 leading-tight">
                                    {employee.position || 'Employee'}
                                  </p>
                                </div>
                              </div>
                              {isSelected && (
                                <span className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded-full">
                                  Selected
                                </span>
                              )}
                            </div>
                          );
                        })
                      ) : (
                        <div className="text-center py-8">
                          <UserIcon size={32} className="text-gray-300 mx-auto mb-2" />
                          <p className="text-sm text-gray-500">No employees available</p>
                        </div>
                      )}
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 mt-2">
                    Click on employees to assign or remove them from this pickup request
                  </p>
                </div>
              </div>
              <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
                <Button
                  variant="outline"
                  onClick={() => setIsEditModalOpen(false)}
                  className="px-6 py-2.5 shadow-sm"
                >
                  Cancel
                </Button>
                <Button type="submit" variant="primary" className="px-6 py-2.5 shadow-sm">
                  Update Pickup Request
                </Button>
              </div>
            </form>
          )}
        </Modal>

        <Modal
          isOpen={isDeleteModalOpen}
          onClose={() => setIsDeleteModalOpen(false)}
          title="Delete Pickup Request"
        >
          {selectedRequest && (
            <div className="text-center">
              <div className="p-4 bg-red-100 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                <TrashIcon size={32} className="text-red-500" />
              </div>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">Delete Pickup Request</h3>
              <p className="text-gray-600 mb-6">
                Are you sure you want to delete the pickup request for{' '}
                <span className="font-semibold text-gray-900">{selectedRequest.username}</span>? This
                action cannot be undone and all associated data will be permanently removed.
              </p>
              <div className="bg-gray-50 rounded-xl p-4 mb-6">
                <div className="text-sm text-gray-600 space-y-1">
                  <p>
                    <span className="font-medium">Customer:</span> {selectedRequest.username}
                  </p>
                  <p>
                    <span className="font-medium">Location:</span> {selectedRequest.location}
                  </p>
                  <p>
                    <span className="font-medium">Date:</span> {selectedRequest.date}
                  </p>
                  <p>
                    <span className="font-medium">Status:</span> {selectedRequest.status}
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
                      const baseUrl = import.meta.env.VITE_API_BASE_URL;
                      await fetch(
                        `${baseUrl}/api/personnel/delete-pickup-request/${selectedRequest.id}`,
                        {
                          method: 'DELETE',
                          headers: { Authorization: `Bearer ${token}` },
                        }
                      );
                      const response = await fetch(
                        `${baseUrl}/api/personnel/get-all-request`,
                        {
                          headers: { Authorization: `Bearer ${token}` },
                        }
                      );
                      const data = await response.json();
                      if (data.success && Array.isArray(data.allPickups)) {
                        setPickupRequests(
                          data.allPickups.map((req: any) => ({
                            id: req._id,
                            username: req.userName,
                            contact: req.contact,
                            location: req.location,
                            imageURL: req.imageUrl,
                            date: req.date ? req.date.slice(0, 10) : '',
                            advance: req.advance,
                            price: req.price,
                            balance: req.balance,
                            status: req.status,
                            staff: req.staff || [],
                          }))
                        );
                      }
                      setIsDeleteModalOpen(false);
                      addToast('success', 'Request Deleted', 'Pickup request has been deleted successfully');
                    } catch (err) {
                      addToast('error', 'Delete Failed', 'Failed to delete pickup request');
                    } finally {
                      setLoading(false);
                    }
                  }}
                  className="px-6 py-2.5 shadow-sm"
                >
                  Delete Request
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