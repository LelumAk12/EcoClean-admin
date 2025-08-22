import React, { useState, useEffect } from 'react';
import { PlusIcon, SearchIcon, TrashIcon, BellIcon, SendIcon, UsersIcon, EyeIcon, CalendarIcon, CheckCircleIcon, XCircleIcon, AlertCircleIcon, InfoIcon, XIcon, EditIcon } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import Button from '../common/Button';
import Table from '../common/Table';
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

/// <reference types="vite/client" />
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

interface User {
  id: string; // This will be mapped from _id
  name: string;
  email: string;
  phone?: string;
  address?: string;
  role?: string;
}

interface Notification {
  id: string;
  title: string;
  message: string;
  type: 'General' | 'Alert' | 'Reward' | 'Reminder' | 'Discount';
  status: 'Read' | 'Unread';
  sentDate?: string;
  scheduledDate?: string;
  readCount?: number;
  totalRecipients?: number;
}

const NotificationManager = () => {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [selectedNotification, setSelectedNotification] = useState<Notification | null>(null);
  const [editNotification, setEditNotification] = useState<Notification | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [updateLoading, setUpdateLoading] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  // User selection states
  const [users, setUsers] = useState<User[]>([]);
  const [selectedUsers, setSelectedUsers] = useState<User[]>([]);
  const [userSearchTerm, setUserSearchTerm] = useState('');
  const [sendToAll, setSendToAll] = useState(false);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState<string | null>(null);

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

  // Fetch all users function
  const fetchUsers = async () => {
    setUsersLoading(true);
    setUsersError(null);
    const token = localStorage.getItem('authToken');
    
    try {
      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      const response = await fetch(`${baseUrl}/api/personnel/getAllCustomers`, {
        headers: {
          'Authorization': token ? `Bearer ${token}` : '',
        }
      });

      if (!response.ok) throw new Error('Failed to fetch users');
      const data = await response.json();
      console.log('Fetch users response:', data);

      if (data.users && Array.isArray(data.users)) {
        const mappedUsers = data.users.map((user: any) => ({
          id: user._id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          address: user.address,
          role: user.role
        }));
        setUsers(mappedUsers);
      } else {
        addToast('error', 'Failed to Load Users', 'Unable to fetch user data from the server.');
      }
    } catch (err: any) {
      console.error('Fetch users error:', err);
      addToast('error', 'Failed to Load Users', 'Unable to fetch user data from the server.');
    } finally {
      setUsersLoading(false);
    }
  };

  // Fetch notifications function
  const fetchNotifications = async () => {
    setLoading(true);
    setError(null);
    const token = localStorage.getItem('authToken');
    try {
      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      const response = await axios.get(`${baseUrl}/api/personnel/get-all-notifications`, {
        headers: {
          'Authorization': token ? `Bearer ${token}` : '',
          'Content-Type': 'application/json'
        }
      });
      const data = response.data;
      if (data.success && Array.isArray(data.data)) {
        // Map notifications
        const mapped = data.data.map((item: any) => ({
          id: item._id,
          title: item.title,
          message: item.message,
          type: item.type || 'General',
          status: item.status || 'Unread',
          sentDate: item.createdAt,
          scheduledDate: undefined,
          readCount: undefined,
          totalRecipients: undefined
        }));
        // If there are multiple notifications with the same title/message/type/status, keep only one (for send-to-all)
        const unique = Object.values(
          mapped.reduce((acc: any, curr: any) => {
            // Use a composite key for notifications sent to all users
            const key = `${curr.title}|${curr.message}|${curr.type}|${curr.status}`;
            acc[key] = curr;
            return acc;
          }, {})
        );
        setNotifications(unique as Notification[]);
      } else {
        addToast('error', 'Failed to Load Notifications', 'Unable to fetch notification data from the server.');
      }
    } catch (err: any) {
      console.error('Fetch notifications error:', err);
      addToast('error', 'Failed to Load Notifications', 'Unable to fetch notification data from the server.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNotifications();
    fetchUsers();
  }, []);
  const columns = [{
    header: 'Title',
    accessor: 'title',
    cell: (value: string, row: Notification) => <div>
          <div className="font-medium text-gray-900 flex items-center">
            {getNotificationIcon(row.type)}
            <span className="ml-2">{value}</span>
          </div>
        </div>
  }, {
    header: 'Message',
    accessor: 'message',
    cell: (value: string) => <div className="text-gray-500 text-sm truncate max-w-xs">
          {value.substring(0, 60)}...
        </div>
  }, {
    header: 'Type',
    accessor: 'type',
    cell: (value: string) => <span className={`px-2 py-1 text-xs font-medium rounded-full ${
      value === 'General' ? 'bg-blue-100 text-blue-800' : 
      value === 'Alert' ? 'bg-red-100 text-red-800' : 
      value === 'Reminder' ? 'bg-yellow-100 text-yellow-800' :
      value === 'Reward' ? 'bg-green-100 text-green-800' :
      value === 'Discount' ? 'bg-purple-100 text-purple-800' :
      'bg-gray-100 text-gray-800'
    }`}>
          {value}
        </span>
  }, {
    header: 'Status',
    accessor: 'status',
    cell: (value: string) => <div>
          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
            value === 'Read' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
          }`}>
            {value}
          </span>
        </div>
  }, {
    header: 'Actions',
    accessor: 'id',
    cell: (_: any, row: Notification) => <div className="flex space-x-2">
      <Button 
        variant="outline" 
        size="sm" 
        icon={<EyeIcon size={14} />} 
        onClick={e => {
          e.stopPropagation();
          setSelectedNotification(row);
          setIsViewModalOpen(true);
        }}
        className="hover:bg-blue-50 hover:border-blue-200 hover:text-blue-700 transition-all duration-200"
      >
        View
      </Button>
      <Button 
        variant="outline" 
        size="sm" 
        icon={<EditIcon size={14} />} 
        onClick={e => {
          e.stopPropagation();
          setEditNotification(row);
          setIsEditModalOpen(true);
        }}
        className="hover:bg-green-50 hover:border-green-200 hover:text-green-700 transition-all duration-200"
      >
        Edit
      </Button>
      <Button 
        variant="danger" 
        size="sm" 
        icon={<TrashIcon size={14} />} 
        onClick={e => {
          e.stopPropagation();
          setSelectedNotification(row);
          setIsDeleteModalOpen(true);
        }}
        className="bg-red-50 text-red-600 border-red-200 hover:bg-red-100 hover:border-red-300 transition-all duration-200"
      >
        Delete
      </Button>
    </div>
  }];
  const filteredNotifications = notifications.filter(notification => (typeFilter === 'all' || notification.type === typeFilter) && (statusFilter === 'all' || notification.status === statusFilter) && (notification.title.toLowerCase().includes(searchTerm.toLowerCase()) || notification.message.toLowerCase().includes(searchTerm.toLowerCase())));
  function getNotificationIcon(type: string) {
    switch (type) {
      case 'General':
        return <InfoIcon size={16} className="text-blue-500" />;
      case 'Alert':
        return <AlertCircleIcon size={16} className="text-red-500" />;
      case 'Reminder':
        return <BellIcon size={16} className="text-yellow-500" />;
      case 'Reward':
        return <CheckCircleIcon size={16} className="text-green-500" />;
      case 'Discount':
        return <XCircleIcon size={16} className="text-purple-500" />;
      default:
        return <BellIcon size={16} className="text-gray-500" />;
    }
  }
  // Delete notification handler
  const handleDeleteNotification = async () => {
    if (!selectedNotification) return;
    const token = localStorage.getItem('authToken');
    try {
      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      await axios.delete(`${baseUrl}/api/personnel/delete-notification/${selectedNotification.id}`, {
        headers: {
          'Authorization': token ? `Bearer ${token}` : '',
          'Content-Type': 'application/json'
        }
      });
      // Refresh notifications from server
      await fetchNotifications();
      setIsDeleteModalOpen(false);
      addToast('success', 'Notification Deleted', 'The notification has been successfully removed from the system.');
    } catch (err) {
      addToast('error', 'Delete Failed', 'Unable to delete notification. Please try again.');
      setIsDeleteModalOpen(false);
    }
  };

  // Create notification handler
  const handleCreateNotification = async (e: React.FormEvent) => {
    e.preventDefault();
    
    setCreateLoading(true);
    setError(null);
    const token = localStorage.getItem('authToken');

    const formData = new FormData(e.target as HTMLFormElement);
    // Ensure userIds is a non-empty array
    let userIds: string[] = [];
    if (sendToAll) {
      // If sending to all users, use all user IDs
      userIds = users.map(user => user.id);
    } else {
      // Use selected users
      userIds = selectedUsers.map(user => user.id);
    }

    // Validate that userIds is not empty
    if (userIds.length === 0) {
      addToast('error', 'No Recipients Selected', 'Please select at least one user or choose "Send to all users".');
      setCreateLoading(false);
      return;
    }

    const notificationData = {
      title: formData.get('title') as string,
      message: formData.get('message') as string,
      type: formData.get('type') as string,
      status: formData.get('status') as string,
      userIds: userIds
    };

    console.log('Creating notification with data:', notificationData);
    console.log('Auth token:', token);

    try {
      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      const response = await axios.post(
        `${baseUrl}/api/personnel/create-notification`,
        notificationData,
        {
          headers: {
            'Authorization': token ? `Bearer ${token}` : '',
            'Content-Type': 'application/json'
          }
        }
      );

      console.log('Create response:', response.data);

      if (response.data.success) {
        // Refresh notifications from server
        await fetchNotifications();
        setIsAddModalOpen(false);
        addToast('success', 'Notification Created', `Successfully created and sent notification "${notificationData.title}" to ${userIds.length} recipient(s).`);
        
        // Reset form and user selection
        (e.target as HTMLFormElement).reset();
        resetUserSelection();
      } else {
        console.error('API returned success: false', response.data);
        addToast('error', 'Creation Failed', response.data.message || 'Failed to create notification. Please try again.');
      }
    } catch (err: any) {
      console.error('Create notification error:', err);
      console.error('Error response:', err.response?.data);
      
      if (err.response?.data?.message) {
        addToast('error', 'Creation Failed', err.response.data.message);
      } else if (err.response?.status === 401) {
        addToast('error', 'Unauthorized', 'Please check your login credentials.');
      } else if (err.response?.status === 403) {
        addToast('error', 'Forbidden', 'You do not have permission to create notifications.');
      } else if (err.response?.status === 400) {
        addToast('error', 'Bad Request', 'Please check your input data.');
      } else {
        addToast('error', 'Creation Failed', 'Failed to create notification. Please try again.');
      }
    } finally {
      setCreateLoading(false);
    }
  };

  // Update notification handler
  const handleUpdateNotification = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editNotification) return;

    setUpdateLoading(true);
    setError(null);
    const token = localStorage.getItem('authToken');

    const formData = new FormData(e.target as HTMLFormElement);
    // Ensure userIds is a non-empty array
    let userIds: string[] = [];
    if (sendToAll) {
      // If sending to all users, use all user IDs
      userIds = users.map(user => user.id);
    } else {
      // Use selected users
      userIds = selectedUsers.map(user => user.id);
    }

    // Validate that userIds is not empty
    if (userIds.length === 0) {
      addToast('error', 'No Recipients Selected', 'Please select at least one user or choose "Send to all users".');
      setUpdateLoading(false);
      return;
    }

    const updatedData = {
      title: formData.get('title') as string,
      message: formData.get('message') as string,
      type: formData.get('type') as string,
      status: formData.get('status') as string,
      userIds: userIds
    };

    console.log('Updating notification with data:', updatedData);
    console.log('Auth token:', token);

    try {
      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      const response = await axios.patch(
        `${baseUrl}/api/personnel/update-notification/${editNotification.id}`,
        updatedData,
        {
          headers: {
            'Authorization': token ? `Bearer ${token}` : '',
            'Content-Type': 'application/json'
          }
        }
      );

      console.log('Update response:', response.data);

      if (response.data.success) {
        // Refresh notifications from server
        await fetchNotifications();
        setIsEditModalOpen(false);
        setEditNotification(null);
        addToast('success', 'Notification Updated', `Successfully updated notification "${updatedData.title}".`);
      } else {
        console.error('API returned success: false', response.data);
        addToast('error', 'Update Failed', response.data.message || 'Failed to update notification. Please try again.');
      }
    } catch (err: any) {
      console.error('Update notification error:', err);
      console.error('Error response:', err.response?.data);
      
      if (err.response?.data?.message) {
        addToast('error', 'Update Failed', err.response.data.message);
      } else if (err.response?.status === 401) {
        addToast('error', 'Unauthorized', 'Please check your login credentials.');
      } else if (err.response?.status === 403) {
        addToast('error', 'Forbidden', 'You do not have permission to update notifications.');
      } else if (err.response?.status === 400) {
        addToast('error', 'Bad Request', 'Please check your input data.');
      } else if (err.response?.status === 404) {
        addToast('error', 'Not Found', 'Notification not found.');
      } else {
        addToast('error', 'Update Failed', 'Failed to update notification. Please try again.');
      }
    } finally {
      setUpdateLoading(false);
    }
  };

  // Filter users based on search term
  const filteredUsers = users.filter(user => 
    user.name.toLowerCase().includes(userSearchTerm.toLowerCase()) ||
    user.email.toLowerCase().includes(userSearchTerm.toLowerCase())
  );

  // Toggle user selection
  const toggleUserSelection = (user: User) => {
    setSelectedUsers(prev => {
      const isSelected = prev.find(u => u.id === user.id);
      if (isSelected) {
        return prev.filter(u => u.id !== user.id);
      } else {
        return [...prev, user];
      }
    });
  };

  // Handle send to all toggle
  const handleSendToAllToggle = (checked: boolean) => {
    setSendToAll(checked);
    if (checked) {
      setSelectedUsers([]);
    }
  };

  // Reset user selection when modal closes
  const resetUserSelection = () => {
    setSelectedUsers([]);
    setSendToAll(false);
    setUserSearchTerm('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50 p-6">
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
              <div className="bg-gradient-to-r from-purple-500 to-indigo-600 p-3 rounded-xl">
                <BellIcon size={28} className="text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-purple-900 to-indigo-900 bg-clip-text text-transparent">
                  Notification Management
                </h1>
                <p className="text-gray-500 mt-1">Manage and send notifications to users across the platform</p>
              </div>
            </div>
            <Button 
              variant="primary" 
              icon={<PlusIcon size={18} />} 
              onClick={() => setIsAddModalOpen(true)} 
              className="bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-600 hover:to-indigo-700 shadow-lg hover:shadow-xl transition-all duration-200"
            >
              Create Notification
            </Button>
          </div>
        </motion.div>

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <motion.div 
            {...pageAnimations.statsCard(0)}
            className="relative bg-gradient-to-br from-purple-50 via-white to-purple-100 rounded-2xl shadow-lg border border-purple-100 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-purple-500/5 via-transparent to-indigo-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-purple-500 to-indigo-600 p-3 rounded-xl shadow-lg">
                  <BellIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-purple-600 bg-purple-100 px-2 py-1 rounded-full">
                    Total
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Total Notifications</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-purple-600 to-indigo-600 bg-clip-text text-transparent">
                  {notifications.length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-purple-500 to-indigo-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((notifications.length / Math.max(notifications.length, 10)) * 100, 100)}%` }}
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
                  <CheckCircleIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-green-600 bg-green-100 px-2 py-1 rounded-full">
                    Read
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Read</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-green-600 to-emerald-600 bg-clip-text text-transparent">
                  {notifications.filter(n => n.status === 'Read').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-green-500 to-emerald-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((notifications.filter(n => n.status === 'Read').length / Math.max(notifications.length, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>

          <motion.div 
            {...pageAnimations.statsCard(2)}
            className="relative bg-gradient-to-br from-gray-50 via-white to-gray-100 rounded-2xl shadow-lg border border-gray-200 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-gray-500/5 via-transparent to-slate-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-gray-500 to-slate-600 p-3 rounded-xl shadow-lg">
                  <XCircleIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-gray-600 bg-gray-100 px-2 py-1 rounded-full">
                    Unread
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Unread</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-gray-600 to-slate-600 bg-clip-text text-transparent">
                  {notifications.filter(n => n.status === 'Unread').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-gray-500 to-slate-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((notifications.filter(n => n.status === 'Unread').length / Math.max(notifications.length, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>

          <motion.div 
            {...pageAnimations.statsCard(3)}
            className="relative bg-gradient-to-br from-red-50 via-white to-red-100 rounded-2xl shadow-lg border border-red-100 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 via-transparent to-orange-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-red-500 to-orange-600 p-3 rounded-xl shadow-lg">
                  <AlertCircleIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-red-600 bg-red-100 px-2 py-1 rounded-full">
                    Alerts
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Alerts</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-red-600 to-orange-600 bg-clip-text text-transparent">
                  {notifications.filter(n => n.type === 'Alert').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-red-500 to-orange-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((notifications.filter(n => n.type === 'Alert').length / Math.max(notifications.length, 1)) * 100, 100)}%` }}
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
                    placeholder="Search notifications by title or message..." 
                    className="w-full pl-10 pr-4 py-3 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent bg-white shadow-sm hover:border-gray-300 transition-colors duration-200" 
                    value={searchTerm} 
                    onChange={e => setSearchTerm(e.target.value)} 
                  />
                </div>
              </div>
              <div className="flex flex-wrap gap-3">
                <select 
                  value={typeFilter} 
                  onChange={e => setTypeFilter(e.target.value)} 
                  className="admin-dropdown admin-dropdown-primary"
                >
                  <option value="all">All Types</option>
                  <option value="General">General</option>
                  <option value="Alert">Alert</option>
                  <option value="Reminder">Reminder</option>
                  <option value="Reward">Reward</option>
                  <option value="Discount">Discount</option>
                </select>
                <select 
                  value={statusFilter} 
                  onChange={e => setStatusFilter(e.target.value)} 
                  className="admin-dropdown admin-dropdown-primary"
                >
                  <option value="all">All Statuses</option>
                  <option value="Read">Read</option>
                  <option value="Unread">Unread</option>
                </select>
              </div>
            </div>
          </div>
          {/* Table Content */}
          <div className="p-6">
            {loading ? (
              <div className="text-center py-12">
                <div className="inline-flex items-center justify-center w-12 h-12 bg-purple-100 rounded-full mb-4">
                  <BellIcon className="w-6 h-6 text-purple-600 animate-pulse" />
                </div>
                <p className="text-gray-500 text-lg">Loading notifications...</p>
              </div>
            ) : error ? (
              <div className="text-center py-12">
                <div className="inline-flex items-center justify-center w-12 h-12 bg-red-100 rounded-full mb-4">
                  <AlertCircleIcon className="w-6 h-6 text-red-600" />
                </div>
                <p className="text-red-600 text-lg font-medium">{error}</p>
                <p className="text-gray-500 mt-2">Please try refreshing the page</p>
                <Button 
                  variant="outline" 
                  onClick={fetchNotifications}
                  className="mt-4"
                >
                  Try Again
                </Button>
              </div>
            ) : filteredNotifications.length === 0 ? (
              <div className="text-center py-12">
                <div className="inline-flex items-center justify-center w-12 h-12 bg-gray-100 rounded-full mb-4">
                  <SearchIcon className="w-6 h-6 text-gray-400" />
                </div>
                <p className="text-gray-500 text-lg">No notifications found</p>
                <p className="text-gray-400 mt-2">Try adjusting your search or filter criteria</p>
              </div>
            ) : (
              <div className="space-y-4">
                <Table 
                  columns={columns} 
                  data={filteredNotifications} 
                  onRowClick={row => {
                    setSelectedNotification(row);
                    setIsViewModalOpen(true);
                  }} 
                />
              </div>
            )}
          </div>
          
          {/* Enhanced Pagination */}
          {!loading && !error && filteredNotifications.length > 0 && (
            <div className="px-6 py-4 border-t border-gray-200 bg-gray-50 rounded-b-2xl">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <p className="text-sm text-gray-600">
                    Showing <span className="font-medium">{filteredNotifications.length}</span> of{' '}
                    <span className="font-medium">{notifications.length}</span> notifications
                  </p>
                  {(typeFilter !== 'all' || statusFilter !== 'all' || searchTerm) && (
                    <span className="px-2 py-1 bg-purple-100 text-purple-800 text-xs rounded-full">
                      Filtered
                    </span>
                  )}
                </div>
                <div className="flex items-center space-x-1">
                  <Button 
                    variant="outline" 
                    size="sm" 
                    className="hover:bg-purple-50 hover:border-purple-200 hover:text-purple-700"
                    disabled
                  >
                    Previous
                  </Button>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    className="bg-purple-50 border-purple-200 text-purple-700"
                  >
                    1
                  </Button>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    className="hover:bg-purple-50 hover:border-purple-200 hover:text-purple-700"
                    disabled
                  >
                    Next
                  </Button>
                </div>
              </div>
            </div>
          )}
        </div>
      {/* Enhanced Create Notification Modal */}
      <Modal isOpen={isAddModalOpen} onClose={() => {
        setIsAddModalOpen(false);
        setError(null);
        resetUserSelection();
      }} title="Create New Notification" size="lg">
        <form className="space-y-6" onSubmit={handleCreateNotification}>
          {error && (
            <div className="p-4 bg-red-50 border border-red-200 text-red-700 rounded-xl flex items-center">
              <AlertCircleIcon size={20} className="mr-3 flex-shrink-0" />
              <div>
                <p className="font-medium">Error</p>
                <p className="text-sm">{error}</p>
              </div>
            </div>
          )}
          
          <div className="grid grid-cols-1 gap-6">
            <div>
              <label htmlFor="title" className="block text-sm font-semibold text-gray-700 mb-2">
                Notification Title *
              </label>
              <input 
                type="text" 
                id="title" 
                name="title"
                className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-colors" 
                placeholder="Enter a clear and descriptive title" 
                required
              />
            </div>
            <div>
              <label htmlFor="message" className="block text-sm font-semibold text-gray-700 mb-2">
                Message Content *
              </label>
              <textarea 
                id="message" 
                name="message"
                rows={5} 
                className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-colors resize-none" 
                placeholder="Write your notification message here..."
                required
              ></textarea>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label htmlFor="type" className="block text-sm font-semibold text-gray-700 mb-2">
                Notification Type
              </label>
              <select 
                id="type" 
                name="type"
                className="admin-dropdown admin-dropdown-primary w-full"
                defaultValue="General"
              >
                <option value="General">General</option>
                <option value="Alert">Alert</option>
                <option value="Reminder">Reminder</option>
                <option value="Reward">Reward</option>
                <option value="Discount">Discount</option>
              </select>
            </div>
            <div>
              <label htmlFor="status" className="block text-sm font-semibold text-gray-700 mb-2">
                Initial Status
              </label>
              <select 
                id="status" 
                name="status"
                className="admin-dropdown admin-dropdown-primary w-full"
                defaultValue="Unread"
              >
                <option value="Unread">Unread</option>
                <option value="Read">Read</option>
              </select>
            </div>
          </div>

          {/* User Selection Section */}
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-2">
              Send To
            </label>
            <div className="flex items-center mb-4">
              <input 
                id="send-to-all" 
                type="checkbox" 
                checked={sendToAll}
                onChange={e => handleSendToAllToggle(e.target.checked)}
                className="h-4 w-4 text-purple-600 border-gray-300 rounded focus:ring-purple-500" 
              />
              <label htmlFor="send-to-all" className="ml-2 block text-sm text-gray-800">
                Send to all users {users.length > 0 && `(${users.length} users)`}
              </label>
            </div>
            {!sendToAll && (
              <div>
                <div className="flex flex-wrap gap-2 mb-4">
                  {selectedUsers.length > 0 ? (
                    selectedUsers.map(user => (
                      <span key={user.id} className="inline-flex items-center px-3 py-1 text-sm font-medium rounded-full bg-purple-100 text-purple-800">
                        {user.name} ({user.email})
                        <button 
                          onClick={() => toggleUserSelection(user)}
                          className="ml-2 text-purple-600 hover:text-purple-800"
                        >
                          &times;
                        </button>
                      </span>
                    ))
                  ) : (
                    <div className="text-sm text-gray-500 py-2">
                      No users selected. Please select users below or choose "Send to all users".
                    </div>
                  )}
                </div>
                <div className="relative">
                  <SearchIcon size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                  <input 
                    type="text" 
                    placeholder="Search users by name or email..." 
                    className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl shadow-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-colors" 
                    value={userSearchTerm} 
                    onChange={e => setUserSearchTerm(e.target.value)} 
                  />
                </div>
                {usersLoading ? (
                  <div className="text-center py-4">
                    <p className="text-gray-500 text-sm">Loading users...</p>
                  </div>
                ) : usersError ? (
                  <div className="text-center py-4">
                    <p className="text-red-600 text-sm">{usersError}</p>
                  </div>
                ) : (
                  <div className="max-h-60 overflow-y-auto mt-2">
                    {filteredUsers.map(user => (
                      <div key={user.id} className="flex items-center justify-between p-3 bg-white border border-gray-200 rounded-xl shadow-sm mb-2 hover:shadow-md transition-shadow duration-200">
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-gray-900 truncate">{user.name}</p>
                          <p className="text-xs text-gray-500 truncate">{user.email}</p>
                        </div>
                        {selectedUsers.find(u => u.id === user.id) ? (
                          <span className="px-3 py-1 text-xs font-medium text-green-700 bg-green-100 rounded-full">
                            Selected
                          </span>
                        ) : (
                          <Button 
                            variant="outline" 
                            size="sm" 
                            onClick={() => toggleUserSelection(user)}
                            className="whitespace-nowrap hover:bg-purple-50 hover:border-purple-200 hover:text-purple-700"
                          >
                            Add
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
          
          <div className="flex justify-end space-x-3 pt-6 border-t border-gray-200">
            <Button 
              variant="outline" 
              onClick={() => {
                setIsAddModalOpen(false);
                setError(null);
                resetUserSelection();
              }}
              disabled={createLoading}
              className="px-6 py-2"
            >
              Cancel
            </Button>
            <Button 
              type="submit" 
              variant="primary" 
              icon={createLoading ? null : <SendIcon size={18} />}
              disabled={createLoading || (!sendToAll && selectedUsers.length === 0)}
              className="px-6 py-2 bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-600 hover:to-indigo-700 shadow-lg hover:shadow-xl transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {createLoading ? (
                <div className="flex items-center">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Creating...
                </div>
              ) : (
                `Create & Send ${sendToAll ? `to All (${users.length})` : selectedUsers.length > 0 ? `to ${selectedUsers.length} Users` : ''}`
              )}
            </Button>
          </div>
        </form>
      </Modal>
      {/* Enhanced View Notification Modal */}
      <Modal isOpen={isViewModalOpen} onClose={() => setIsViewModalOpen(false)} title="Notification Details" size="lg">
        {selectedNotification && (
          <div className="space-y-6">
            {/* Header with Icon and Title */}
            <div className="flex items-start space-x-4 p-6 bg-gradient-to-r from-purple-50 to-indigo-50 rounded-xl border border-purple-200">
              <div className="flex-shrink-0 p-3 bg-white rounded-xl shadow-sm">
                {getNotificationIcon(selectedNotification.type)}
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-xl font-bold text-gray-900 mb-2">
                  {selectedNotification.title}
                </h3>
                <div className="flex flex-wrap gap-2">
                  <span className={`inline-flex items-center px-3 py-1 text-sm font-medium rounded-full ${
                    selectedNotification.type === 'General' ? 'bg-blue-100 text-blue-800' : 
                    selectedNotification.type === 'Alert' ? 'bg-red-100 text-red-800' :
                    selectedNotification.type === 'Reminder' ? 'bg-yellow-100 text-yellow-800' :
                    selectedNotification.type === 'Reward' ? 'bg-green-100 text-green-800' :
                    selectedNotification.type === 'Discount' ? 'bg-purple-100 text-purple-800' :
                    'bg-gray-100 text-gray-800'
                  }`}>
                    {selectedNotification.type}
                  </span>
                  <span className={`inline-flex items-center px-3 py-1 text-sm font-medium rounded-full ${
                    selectedNotification.status === 'Read' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                  }`}>
                    {selectedNotification.status}
                  </span>
                </div>
              </div>
            </div>

            {/* Message Content */}
            <div className="bg-white border border-gray-200 rounded-xl p-6">
              <h4 className="text-sm font-semibold text-gray-700 mb-3 uppercase tracking-wide">
                Message Content
              </h4>
              <p className="text-gray-800 leading-relaxed whitespace-pre-line text-base">
                {selectedNotification.message}
              </p>
            </div>

            {/* Metadata */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-gray-50 rounded-xl p-4 border border-gray-200">
                <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
                  <CalendarIcon size={16} className="mr-2" />
                  Created Date
                </h4>
                <p className="text-gray-800 font-medium">
                  {selectedNotification.sentDate && new Date(selectedNotification.sentDate).toLocaleString()}
                </p>
              </div>
              <div className="bg-gray-50 rounded-xl p-4 border border-gray-200">
                <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center">
                  <UsersIcon size={16} className="mr-2" />
                  Status
                </h4>
                <p className="text-gray-800 font-medium">
                  {selectedNotification.status}
                </p>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end space-x-3 pt-6 border-t border-gray-200">
              <Button 
                variant="outline" 
                onClick={() => setIsViewModalOpen(false)}
                className="px-6 py-2"
              >
                Close
              </Button>
              <Button 
                variant="primary" 
                icon={<EditIcon size={16} />} 
                onClick={() => {
                  setEditNotification(selectedNotification);
                  setIsViewModalOpen(false);
                  setIsEditModalOpen(true);
                }}
                className="px-6 py-2 bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-600 hover:to-indigo-700"
              >
                Edit Notification
              </Button>
            </div>
          </div>
        )}
      </Modal>
      {/* Enhanced Delete Confirmation Modal */}
      <Modal isOpen={isDeleteModalOpen} onClose={() => setIsDeleteModalOpen(false)} title="Delete Notification">
        {selectedNotification && (
          <div>
            <div className="flex items-start space-x-4">
              <div className="flex-shrink-0 p-3 bg-red-100 rounded-full">
                <TrashIcon className="h-6 w-6 text-red-600" />
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                  Confirm Deletion
                </h3>
                <p className="text-gray-600 mb-4">
                  Are you sure you want to delete the notification{' '}
                  <span className="font-semibold text-gray-900">"{selectedNotification.title}"</span>?
                </p>
                <div className="bg-red-50 border border-red-200 rounded-xl p-4">
                  <p className="text-red-800 text-sm font-medium">
                    Warning: This action cannot be undone
                  </p>
                  <p className="text-red-700 text-sm mt-1">
                    The notification will be permanently removed from the system.
                  </p>
                </div>
              </div>
            </div>
            
            <div className="flex justify-end space-x-3 mt-8 pt-6 border-t border-gray-200">
              <Button 
                variant="outline" 
                onClick={() => setIsDeleteModalOpen(false)}
                className="px-6 py-2"
              >
                Cancel
              </Button>
              <Button 
                variant="danger" 
                onClick={handleDeleteNotification}
                icon={<TrashIcon size={16} />}
                className="px-6 py-2 bg-red-600 hover:bg-red-700 shadow-lg hover:shadow-xl transition-all duration-200"
              >
                Delete Notification
              </Button>
            </div>
          </div>
        )}
      </Modal>
      {/* Enhanced Edit Notification Modal */}
      <Modal isOpen={isEditModalOpen} onClose={() => setIsEditModalOpen(false)} title="Edit Notification" size="lg">
        {editNotification && (
          <form className="space-y-6" onSubmit={handleUpdateNotification}>
            {error && (
              <div className="p-4 bg-red-50 border border-red-200 text-red-700 rounded-xl flex items-center">
                <AlertCircleIcon size={20} className="mr-3 flex-shrink-0" />
                <div>
                  <p className="font-medium">Error</p>
                  <p className="text-sm">{error}</p>
                </div>
              </div>
            )}
            
            <div className="grid grid-cols-1 gap-6">
              <div>
                <label htmlFor="edit-title" className="block text-sm font-semibold text-gray-700 mb-2">
                  Notification Title *
                </label>
                <input 
                  type="text" 
                  id="edit-title" 
                  name="title"
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-colors" 
                  defaultValue={editNotification.title}
                  required
                />
              </div>
              <div>
                <label htmlFor="edit-message" className="block text-sm font-semibold text-gray-700 mb-2">
                  Message Content *
                </label>
                <textarea 
                  id="edit-message" 
                  name="message"
                  rows={5} 
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-colors resize-none" 
                  defaultValue={editNotification.message}
                  required
                ></textarea>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="edit-type" className="block text-sm font-semibold text-gray-700 mb-2">
                  Notification Type
                </label>
                <select 
                  id="edit-type" 
                  name="type"
                  className="admin-dropdown admin-dropdown-primary w-full" 
                  defaultValue={editNotification.type}
                >
                  <option value="General">General</option>
                  <option value="Alert">Alert</option>
                  <option value="Reminder">Reminder</option>
                  <option value="Reward">Reward</option>
                  <option value="Discount">Discount</option>
                </select>
              </div>
              <div>
                <label htmlFor="edit-status" className="block text-sm font-semibold text-gray-700 mb-2">
                  Status
                </label>
                <select 
                  id="edit-status" 
                  name="status"
                  className="admin-dropdown admin-dropdown-primary w-full" 
                  defaultValue={editNotification.status}
                >
                  <option value="Unread">Unread</option>
                  <option value="Read">Read</option>
                </select>
              </div>
            </div>

            {/* User Selection Section */}
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Send To
              </label>
              <div className="flex items-center mb-4">
                <input 
                  id="send-to-all" 
                  type="checkbox" 
                  checked={sendToAll}
                  onChange={e => setSendToAll(e.target.checked)}
                  className="h-4 w-4 text-purple-600 border-gray-300 rounded focus:ring-purple-500" 
                />
                <label htmlFor="send-to-all" className="ml-2 block text-sm text-gray-800">
                  Send to all users
                </label>
              </div>
              {!sendToAll && (
                <div>
                  <div className="flex flex-wrap gap-2 mb-4">
                    {selectedUsers.map(user => (
                      <span key={user.id} className="inline-flex items-center px-3 py-1 text-sm font-medium rounded-full bg-purple-100 text-purple-800">
                        {user.name} ({user.email})
                        <button 
                          onClick={() => setSelectedUsers(prev => prev.filter(u => u.id !== user.id))}
                          className="ml-2 text-purple-600 hover:text-purple-800"
                        >
                          &times;
                        </button>
                      </span>
                    ))}
                  </div>
                  <div className="relative">
                    <SearchIcon size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                    <input 
                      type="text" 
                      placeholder="Search users by name or email..." 
                      className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl shadow-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-colors" 
                      value={userSearchTerm} 
                      onChange={e => setUserSearchTerm(e.target.value)} 
                    />
                  </div>
                  {usersLoading ? (
                    <div className="text-center py-4">
                      <p className="text-gray-500 text-sm">Loading users...</p>
                    </div>
                  ) : usersError ? (
                    <div className="text-center py-4">
                      <p className="text-red-600 text-sm">{usersError}</p>
                    </div>
                  ) : (
                    <div className="max-h-60 overflow-y-auto mt-2">
                      {filteredUsers.map(user => (
                        <div key={user.id} className="flex items-center justify-between p-3 bg-white border border-gray-200 rounded-xl shadow-sm mb-2 hover:shadow-md transition-shadow duration-200">
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-gray-900 truncate">{user.name}</p>
                            <p className="text-xs text-gray-500 truncate">{user.email}</p>
                          </div>
                          <Button 
                            variant="outline" 
                            size="sm" 
                            onClick={() => {
                              setSelectedUsers(prev => [...prev, user]);
                              setUserSearchTerm('');
                            }}
                            className="whitespace-nowrap hover:bg-purple-50 hover:border-purple-200 hover:text-purple-700"
                          >
                            Add
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex justify-end space-x-3 pt-6 border-t border-gray-200">
              <Button 
                variant="outline" 
                onClick={() => {
                  setIsEditModalOpen(false);
                  setError(null);
                }}
                disabled={updateLoading}
                className="px-6 py-2"
              >
                Cancel
              </Button>
              <Button 
                type="submit" 
                variant="primary" 
                icon={updateLoading ? null : <SendIcon size={18} />}
                disabled={updateLoading}
                className="px-6 py-2 bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-600 hover:to-indigo-700 shadow-lg hover:shadow-xl transition-all duration-200"
              >
                {updateLoading ? (
                  <div className="flex items-center">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Updating...
                  </div>
                ) : (
                  'Update Notification'
                )}
              </Button>
            </div>
          </form>
        )}
      </Modal>
      </div>
    </div>
  );
};
export default NotificationManager;
