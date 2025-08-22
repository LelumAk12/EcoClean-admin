/// <reference types="vite/client" />
import React, { useState, useEffect } from 'react';
import { PlusIcon, EditIcon, TrashIcon, PackageIcon, DollarSignIcon, PercentIcon, ImageIcon, ToggleLeftIcon, ToggleRightIcon, CheckCircleIcon, XCircleIcon, AlertCircleIcon, XIcon, SearchIcon } from 'lucide-react';
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
    }, 6000); // Increased to 6 seconds

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
      
      {/* Progress bar */}
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
interface Service {
  id: number;
  name: string;
  description: string;
  price: number;
  discount: number;
  imageURL: string;
  availability: boolean;
}
const ServicesManager = () => {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [selectedService, setSelectedService] = useState<Service | null>(null);
  const [availabilityFilter, setAvailabilityFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [addImageFile, setAddImageFile] = useState<File | null>(null);
  const [services, setServices] = useState<Service[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [toasts, setToasts] = useState<Toast[]>([]);

  // Toast helper functions
  const addToast = (type: ToastType, title: string, message: string) => {
    const newToast: Toast = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type,
      title,
      message,
    };
    console.log('Adding toast:', newToast); // Debug log
    setToasts(prev => {
      const updated = [...prev, newToast];
      console.log('Updated toasts array:', updated); // Debug log
      return updated;
    });
  };

  const removeToast = (id: string) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  };

  const fetchServices = async () => {
    setIsLoading(true);
    try {
      const token = localStorage.getItem('authToken');
      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      const res = await fetch(`${baseUrl}/api/personnel/get-all-services`, {
        headers: {
          Authorization: token ? `Bearer ${token}` : '',
        },
      });
      if (!res.ok) throw new Error('Failed to fetch services');
      const data = await res.json();
      console.log('Fetched services data:', data); // Debug log
      const mapped = (data.data || []).map((svc: any) => {
        console.log('Service object:', svc); // Debug individual service
        console.log('Image fields - imageUrl:', svc.imageUrl, 'image:', svc.image); // Debug image fields
        return {
          id: svc._id,
          name: svc.serviceName,
          description: svc.description,
          price: svc.price,
          discount: svc.discount,
          imageURL: svc.imageUrl || svc.image || '', // Use imageUrl since that's what's returned
          availability: svc.Availability === true,
        };
      });
      setServices(mapped);
    } catch (err) {
      setServices([]);
      addToast('error', 'Failed to Load Services', 'Unable to fetch services from the server. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchServices();
  }, []);
  const filteredServices = services.filter(service => {
    const matchesAvailability = availabilityFilter === 'all' ||
      (availabilityFilter === 'available' && service.availability) ||
      (availabilityFilter === 'unavailable' && !service.availability);
    
    const matchesSearch = searchTerm === '' ||
      service.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      service.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesAvailability && matchesSearch;
  });
  return (
    <>
      {/* Global dropdown styles are imported from global-dropdown.css */}
      
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 p-6">
      {/* Toast Container */}
      <ToastContainer toasts={toasts} onRemove={removeToast} />
      
      {/* Debug Info - Remove in production */}
      {toasts.length > 0 && (
        <div className="fixed bottom-4 left-4 bg-black text-white px-3 py-1 rounded text-xs z-[9999]">
          Active toasts: {toasts.length}
        </div>
      )}
      
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Enhanced Header Section */}
        <motion.div 
          {...pageAnimations.header}
          className="bg-white rounded-2xl shadow-xl border border-gray-100 p-8"
        >
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
            {/* Title Section - Left Side */}
            <div className="flex items-center">
              <div className="p-4 bg-gradient-to-r from-blue-500 to-indigo-600 rounded-2xl shadow-lg mr-4">
                <PackageIcon size={32} className="text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-blue-900 to-indigo-900 bg-clip-text text-transparent">
                  Services Management
                </h1>
                <p className="text-gray-600 mt-2 text-lg">
                  Manage your service offerings and pricing with ease
                </p>
              </div>
            </div>
            
            {/* Action Button - Right Side */}
            <div className="flex flex-col sm:flex-row gap-4 flex-shrink-0">
              <Button 
                variant="primary" 
                icon={<PlusIcon size={18} />} 
                onClick={() => setIsAddModalOpen(true)}
                className="px-6 py-3 bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 shadow-lg hover:shadow-xl transition-all duration-200"
              >
                Add New Service
              </Button>
            </div>
          </div>
        </motion.div>

        {/* Enhanced Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <motion.div 
            {...pageAnimations.statsCard(0)}
            className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-xl transition-all duration-300 hover:-translate-y-1 group"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Total Services</p>
                <p className="text-3xl font-bold text-gray-900 mb-2">{services.length}</p>
                <div className="flex items-center text-xs text-gray-500">
                  <div className="w-2 h-2 bg-blue-400 rounded-full mr-2"></div>
                  All service offerings
                </div>
              </div>
              <div className="p-4 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-110">
                <PackageIcon size={28} className="text-white" />
              </div>
            </div>
            {/* Progress indicator */}
            <div className="mt-4 pt-4 border-t border-gray-100">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500">Service Portfolio</span>
                <span className="text-blue-600 font-medium">Active</span>
              </div>
              <div className="mt-2 w-full bg-gray-200 rounded-full h-1.5">
                <div className="bg-gradient-to-r from-blue-500 to-indigo-600 h-1.5 rounded-full transition-all duration-500" style={{width: '100%'}}></div>
              </div>
            </div>
          </motion.div>

          <motion.div 
            {...pageAnimations.statsCard(1)}
            className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-xl transition-all duration-300 hover:-translate-y-1 group"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Available</p>
                <p className="text-3xl font-bold text-green-600 mb-2">{services.filter(s => s.availability).length}</p>
                <div className="flex items-center text-xs text-gray-500">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                  Ready for customers
                </div>
              </div>
              <div className="p-4 bg-gradient-to-br from-green-500 to-emerald-600 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-110">
                <ToggleRightIcon size={28} className="text-white" />
              </div>
            </div>
            {/* Progress indicator */}
            <div className="mt-4 pt-4 border-t border-gray-100">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500">Availability Rate</span>
                <span className="text-green-600 font-medium">
                  {services.length > 0 ? Math.round((services.filter(s => s.availability).length / services.length) * 100) : 0}%
                </span>
              </div>
              <div className="mt-2 w-full bg-gray-200 rounded-full h-1.5">
                <div 
                  className="bg-gradient-to-r from-green-500 to-emerald-600 h-1.5 rounded-full transition-all duration-500" 
                  style={{width: `${services.length > 0 ? Math.round((services.filter(s => s.availability).length / services.length) * 100) : 0}%`}}
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
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Unavailable</p>
                <p className="text-3xl font-bold text-red-600 mb-2">{services.filter(s => !s.availability).length}</p>
                <div className="flex items-center text-xs text-gray-500">
                  <div className="w-2 h-2 bg-red-400 rounded-full mr-2"></div>
                  Currently inactive
                </div>
              </div>
              <div className="p-4 bg-gradient-to-br from-red-500 to-pink-600 rounded-2xl shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-110">
                <ToggleLeftIcon size={28} className="text-white" />
              </div>
            </div>
            {/* Progress indicator */}
            <div className="mt-4 pt-4 border-t border-gray-100">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500">Inactive Rate</span>
                <span className="text-red-600 font-medium">
                  {services.length > 0 ? Math.round((services.filter(s => !s.availability).length / services.length) * 100) : 0}%
                </span>
              </div>
              <div className="mt-2 w-full bg-gray-200 rounded-full h-1.5">
                <div 
                  className="bg-gradient-to-r from-red-500 to-pink-600 h-1.5 rounded-full transition-all duration-500" 
                  style={{width: `${services.length > 0 ? Math.round((services.filter(s => !s.availability).length / services.length) * 100) : 0}%`}}
                ></div>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Services Grid */}
        <motion.div 
          {...pageAnimations.mainContent}
          className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden"
        >
          <div className="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <h4 className="text-lg font-semibold text-gray-800">Services Catalog</h4>
          </div>
          
          {/* Enhanced Search and Filter Section */}
          <div className="p-6 border-b border-gray-200 bg-gradient-to-r from-gray-50 to-white">
            <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center space-y-4 lg:space-y-0">
              <div className="flex-1 max-w-md">
                <div className="relative">
                  <SearchIcon size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                  <input 
                    type="text" 
                    placeholder="Search services by name or description..." 
                    className="w-full pl-10 pr-4 py-3 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white shadow-sm hover:border-gray-300 transition-colors duration-200" 
                    value={searchTerm} 
                    onChange={e => setSearchTerm(e.target.value)} 
                  />
                </div>
              </div>
              <div className="flex flex-wrap gap-3">
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-600 font-medium">Filter by Availability:</span>
                  <select 
                    value={availabilityFilter} 
                    onChange={e => setAvailabilityFilter(e.target.value)} 
                    className="admin-dropdown admin-dropdown-primary"
                  >
                    <option value="all">All Statuses</option>
                    <option value="available">Available</option>
                    <option value="unavailable">Unavailable</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
          
          <div className="p-8">
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8 lg:gap-10">
          {isLoading ? (
            // Loading skeleton with improved design
            Array.from({ length: 6 }).map((_, index) => (
              <div key={index} className="bg-white rounded-3xl shadow-md border border-gray-100 overflow-hidden animate-pulse">
                <div className="h-56 bg-gradient-to-br from-gray-100 to-gray-200"></div>
                <div className="p-6 space-y-4">
                  <div className="space-y-3">
                    <div className="h-6 bg-gray-200 rounded-lg"></div>
                    <div className="space-y-2">
                      <div className="h-4 bg-gray-200 rounded"></div>
                      <div className="h-4 bg-gray-200 rounded w-3/4"></div>
                    </div>
                  </div>
                  <div className="h-16 bg-gray-100 rounded-2xl"></div>
                  <div className="flex space-x-3 pt-2">
                    <div className="h-10 bg-gray-200 rounded-xl flex-1"></div>
                    <div className="h-10 bg-gray-200 rounded-xl flex-1"></div>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <>
              {filteredServices.map(service => 
                <ServiceCard 
                  key={service.id} 
                  service={service} 
                  onEdit={() => {
                    setSelectedService(service);
                    setIsEditModalOpen(true);
                  }} 
                  onDelete={() => {
                    setSelectedService(service);
                    setIsDeleteModalOpen(true);
                  }} 
                />
              )}
              {filteredServices.length === 0 && (
                <div className="col-span-full py-20 text-center">
                  <div className="bg-white rounded-3xl shadow-md border border-gray-100 p-16 max-w-md mx-auto">
                    <div className="mb-8">
                      <div className="w-20 h-20 bg-gradient-to-br from-blue-100 to-indigo-100 rounded-full flex items-center justify-center mx-auto mb-6">
                        <PackageIcon size={40} className="text-blue-500" />
                      </div>
                      <h3 className="text-2xl font-bold text-gray-800 mb-3">
                        {services.length === 0 ? 'No Services Available' : 'No Services Found'}
                      </h3>
                      <p className="text-gray-600 leading-relaxed">
                        {services.length === 0 
                          ? 'Start building your service catalog by adding your first service offering.'
                          : searchTerm 
                            ? 'Try adjusting your search terms or filters to find what you\'re looking for.'
                            : 'No services match your current filter criteria. Try selecting different options.'
                        }
                      </p>
                    </div>
                    {services.length === 0 && (
                      <Button 
                        variant="primary" 
                        icon={<PlusIcon size={18} />} 
                        onClick={() => setIsAddModalOpen(true)}
                        className="px-8 py-3 bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 shadow-lg hover:shadow-xl transition-all duration-200 rounded-xl font-medium"
                      >
                        Add Your First Service
                      </Button>
                    )}
                  </div>
                </div>
              )}
            </>
          )}
            </div>
          </div>
        </motion.div>
      </div>

      {/* Add New Service Modal */}
      <Modal isOpen={isAddModalOpen} onClose={() => {
        setIsAddModalOpen(false);
        setAddImageFile(null);
      }} title="Add New Service" size="lg">
        <div className="mb-6">
          <p className="text-gray-600">Create a new service offering for your customers with detailed information and pricing.</p>
        </div>
        <form className="space-y-6" onSubmit={async (e) => {
          e.preventDefault();
          
          const form = e.target as HTMLFormElement;
          const formData = new FormData(form);
          
          const imageFile = addImageFile;
          if (!imageFile) {
            addToast('warning', 'Image Required', 'Please select an image for the service.');
            return;
          }

          // Create FormData for multipart/form-data request
          const payload = new FormData();
          
          // Append individual fields for better compatibility
          payload.append('serviceName', formData.get('name') as string);
          payload.append('description', formData.get('description') as string);
          payload.append('price', formData.get('price') as string);
          payload.append('discount', formData.get('discount') as string);
          payload.append('Availability', formData.get('availability') === 'on' ? 'true' : 'false');
          payload.append('image', imageFile);

          // Debug: Log all FormData entries
          console.log('Add Service FormData entries:');
          for (const [key, value] of payload.entries()) {
            console.log(key, value);
          }

          try {
            const token = localStorage.getItem('authToken');
            const baseUrl = import.meta.env.VITE_API_BASE_URL;
            const res = await fetch(`${baseUrl}/api/personnel/add-new-service`, {
              method: 'POST',
              headers: {
                Authorization: token ? `Bearer ${token}` : '',
                // Remove Content-Type header to let the browser set it automatically for FormData
              },
              body: payload,
            });
            
            if (!res.ok) {
              const errorData = await res.text();
              console.error('Add service failed:', res.status, errorData);
              throw new Error(`Failed to add service: ${res.status} ${res.statusText}`);
            }

            const responseData = await res.json();
            console.log('Add service response:', responseData);

            addToast('success', 'Service Created!', `"${formData.get('name')}" has been successfully added to your services.`);
            setIsAddModalOpen(false);
            setAddImageFile(null);
            fetchServices(); // Refresh the services list
          } catch (err: any) {
            console.error('Add service error:', err);
            addToast('error', 'Failed to Create Service', err.message || 'There was an error creating the service. Please try again.');
          }
        }}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="md:col-span-2">
              <label htmlFor="name" className="block text-sm font-semibold text-gray-700 mb-2">
                Service Name
              </label>
              <input 
                type="text" 
                id="name" 
                name="name" 
                className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 hover:border-gray-400" 
                placeholder="Enter a compelling service name" 
                required 
              />
            </div>
            <div className="md:col-span-2">
              <label htmlFor="description" className="block text-sm font-semibold text-gray-700 mb-2">
                Description
              </label>
              <textarea 
                id="description" 
                name="description" 
                rows={4} 
                className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 hover:border-gray-400 resize-none" 
                placeholder="Describe what makes this service special..." 
                required
              ></textarea>
            </div>
            <div>
              <label htmlFor="price" className="block text-sm font-semibold text-gray-700 mb-2">
                Price (LKR)
              </label>
              <div className="relative">
                <DollarSignIcon size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                <input 
                  type="number" 
                  id="price" 
                  name="price" 
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 hover:border-gray-400" 
                  placeholder="0.00" 
                  required 
                />
              </div>
            </div>
            <div>
              <label htmlFor="discount" className="block text-sm font-semibold text-gray-700 mb-2">
                Discount (%)
              </label>
              <div className="relative">
                <PercentIcon size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                <input 
                  type="number" 
                  id="discount" 
                  name="discount" 
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 hover:border-gray-400" 
                  placeholder="0" 
                  min="0" 
                  max="100" 
                  required 
                />
              </div>
            </div>
            <div className="md:col-span-2">
              <label htmlFor="image" className="block text-sm font-semibold text-gray-700 mb-2">
                Service Image
              </label>
              <div className="relative">
                <input 
                  type="file" 
                  id="image" 
                  name="image" 
                  accept="image/*" 
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 hover:border-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100" 
                  required 
                  onChange={e => setAddImageFile(e.target.files ? e.target.files[0] : null)} 
                />
              </div>
            </div>
            <div className="md:col-span-2">
              <div className="flex items-center p-4 bg-green-50 rounded-xl border border-green-200">
                <input 
                  id="availability" 
                  name="availability" 
                  type="checkbox" 
                  className="h-5 w-5 text-green-600 focus:ring-green-500 border-gray-300 rounded" 
                />
                <label htmlFor="availability" className="ml-3 block text-sm font-medium text-green-800">
                  Service is available for customers
                </label>
              </div>
            </div>
          </div>
          <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
            <Button 
              variant="outline" 
              onClick={() => {
                setIsAddModalOpen(false);
                setAddImageFile(null);
              }}
              className="px-6 py-3 hover:bg-gray-50 transition-all duration-200"
            >
              Cancel
            </Button>
            <Button 
              type="submit" 
              variant="primary"
              className="px-6 py-3 bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 shadow-lg hover:shadow-xl transition-all duration-200"
            >
              Create Service
            </Button>
          </div>
        </form>
      </Modal>
      {/* Edit Service Modal */}
      <Modal isOpen={isEditModalOpen} onClose={() => setIsEditModalOpen(false)} title="Edit Service" size="lg">
        {selectedService && (
          <EditServiceForm
            service={selectedService}
            onClose={() => setIsEditModalOpen(false)}
            onUpdated={async () => {
              // Refresh the services list after update
              fetchServices();
              addToast('success', 'Service Updated!', 'The service has been successfully updated.');
            }}
            addToast={addToast}
          />
        )}
      </Modal>
      {/* Delete Confirmation Modal */}
      <Modal isOpen={isDeleteModalOpen} onClose={() => setIsDeleteModalOpen(false)} title="Delete Service">
        {selectedService && (
          <div className="text-center">
            <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-red-100 mb-6">
              <TrashIcon size={32} className="text-red-600" />
            </div>
            <h3 className="text-lg font-semibold text-gray-900 mb-2">
              Are you sure you want to delete this service?
            </h3>
            <p className="text-gray-600 mb-1">
              You're about to delete <strong>"{selectedService.name}"</strong>
            </p>
            <p className="text-sm text-gray-500 mb-8">
              This action cannot be undone and may affect existing service requests.
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
                  if (!selectedService) return;
                  try {
                  const token = localStorage.getItem('authToken');
                  const baseUrl = import.meta.env.VITE_API_BASE_URL;
                  const res = await fetch(`${baseUrl}/api/personnel/delete-service/${selectedService.id}`, {
                    method: 'DELETE',
                    headers: {
                      Authorization: token ? `Bearer ${token}` : '',
                    },
                  });
                    if (!res.ok) throw new Error('Failed to delete service');
                    setIsDeleteModalOpen(false);
                    addToast('success', 'Service Deleted!', `"${selectedService.name}" has been successfully removed from your services.`);
                    fetchServices(); // Refresh the services list
                  } catch (err) {
                    addToast('error', 'Failed to Delete Service', 'There was an error deleting the service. Please try again.');
                  }
                }}
                className="px-6 py-3 bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 shadow-lg hover:shadow-xl transition-all duration-200"
              >
                Delete Service
              </Button>
            </div>
          </div>
        )}
      </Modal>
      </div>
    </>
  );
};
interface ServiceCardProps {
  service: Service;
  onEdit: () => void;
  onDelete: () => void;
}
const ServiceCard = ({
  service,
  onEdit,
  onDelete
}: ServiceCardProps) => {
  return (
    <motion.div 
      whileHover={{ y: -5, scale: 1.01 }} 
      className="bg-white rounded-3xl shadow-md border border-gray-100 overflow-hidden hover:shadow-2xl transition-all duration-300 group relative"
    >
      {/* Image Section */}
      <div className="h-56 overflow-hidden relative bg-gradient-to-br from-blue-50 to-indigo-50">
        {service.imageURL ? (
          <img 
            src={service.imageURL} 
            alt={service.name} 
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" 
          />
        ) : (
          <div className="w-full h-full bg-gradient-to-br from-gray-50 to-gray-100 flex items-center justify-center">
            <div className="text-center">
              <ImageIcon size={48} className="text-gray-300 mx-auto mb-2" />
              <p className="text-xs text-gray-400 font-medium">No Image</p>
            </div>
          </div>
        )}
        
        {/* Gradient Overlay */}
        <div className="absolute inset-0 bg-gradient-to-t from-black/20 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
        
        {/* Availability Badge */}
        <div className="absolute top-4 right-4">
          {service.availability ? (
            <span className="flex items-center px-3 py-2 text-xs font-bold text-emerald-700 bg-emerald-50 backdrop-blur-md rounded-full border border-emerald-200 shadow-lg">
              <div className="w-2 h-2 bg-emerald-500 rounded-full mr-2 animate-pulse" />
              Available
            </span>
          ) : (
            <span className="flex items-center px-3 py-2 text-xs font-bold text-red-700 bg-red-50 backdrop-blur-md rounded-full border border-red-200 shadow-lg">
              <div className="w-2 h-2 bg-red-500 rounded-full mr-2" />
              Unavailable
            </span>
          )}
        </div>

        {/* Discount Badge */}
        {service.discount > 0 && (
          <div className="absolute top-4 left-4">
            <span className="flex items-center px-3 py-2 text-xs font-bold text-white bg-gradient-to-r from-orange-500 to-red-500 rounded-full shadow-lg">
              <PercentIcon size={12} className="mr-1" />
              {service.discount}% OFF
            </span>
          </div>
        )}
      </div>

      {/* Content Section */}
      <div className="p-6 space-y-4">
        {/* Title and Description */}
        <div className="space-y-3">
          <h3 className="font-bold text-xl text-gray-900 group-hover:text-blue-600 transition-colors duration-200 truncate">
            {service.name}
          </h3>
          <p className="text-sm text-gray-600 leading-relaxed min-h-[2.5rem]" style={{
            display: '-webkit-box',
            WebkitLineClamp: 2,
            WebkitBoxOrient: 'vertical',
            overflow: 'hidden'
          }}>
            {service.description}
          </p>
        </div>

        {/* Price Section */}
        <div className="bg-gradient-to-r from-gray-50 to-blue-50 rounded-2xl p-4 border border-gray-100">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-100 rounded-xl">
                <DollarSignIcon size={18} className="text-blue-600" />
              </div>
              <div>
                <p className="text-xs text-gray-500 font-medium uppercase tracking-wider">Price</p>
                <div className="flex items-baseline space-x-2">
                  {service.discount > 0 ? (
                    <>
                      <span className="text-lg font-bold text-gray-900">
                        LKR {Math.round(service.price * (1 - service.discount / 100)).toLocaleString()}
                      </span>
                      <span className="text-sm text-gray-400 line-through">
                        LKR {service.price.toLocaleString()}
                      </span>
                    </>
                  ) : (
                    <span className="text-lg font-bold text-gray-900">
                      LKR {service.price.toLocaleString()}
                    </span>
                  )}
                </div>
              </div>
            </div>
            
            {service.discount > 0 && (
              <div className="text-right">
                <p className="text-xs text-green-600 font-medium">You Save</p>
                <p className="text-sm font-bold text-green-600">
                  LKR {Math.round((service.price * service.discount) / 100).toLocaleString()}
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex space-x-3 pt-2">
          <Button 
            variant="outline" 
            size="sm" 
            icon={<EditIcon size={16} />} 
            onClick={onEdit}
            className="flex-1 py-3 border-2 border-blue-200 text-blue-600 hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 font-medium transition-all duration-200 rounded-xl"
          >
            Edit
          </Button>
          <Button 
            variant="danger" 
            size="sm" 
            icon={<TrashIcon size={16} />} 
            onClick={onDelete}
            className="flex-1 py-3 font-medium transition-all duration-200 rounded-xl shadow-md hover:shadow-lg"
          >
            Delete
          </Button>
        </div>
      </div>

      {/* Subtle border highlight on hover */}
      <div className="absolute inset-0 rounded-3xl border-2 border-transparent group-hover:border-blue-200 transition-colors duration-300 pointer-events-none" />
    </motion.div>
  );
};
const EditServiceForm = ({ service, onClose, onUpdated, addToast }: { service: Service, onClose: () => void, onUpdated: () => void, addToast: (type: ToastType, title: string, message: string) => void }) => {
  const [name, setName] = useState(service.name);
  const [description, setDescription] = useState(service.description);
  const [price, setPrice] = useState(service.price);
  const [discount, setDiscount] = useState(service.discount);
  const [availability, setAvailability] = useState(service.availability);
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleRemoveImage = () => setImageFile(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    try {
      const token = localStorage.getItem('authToken');
      
      // Create updateData object exactly like Postman
      const updateData = {
        serviceName: name,
        description: description,
        price: Number(price),
        discount: Number(discount),
        Availability: availability,
      };
      
      const formData = new FormData();
      
      // Add updateData as JSON string (exactly like Postman)
      formData.append('updateData', JSON.stringify(updateData));
      
      if (imageFile) {
        formData.append('image', imageFile); // Add image file
        console.log('Image file attached:', imageFile.name, imageFile.type, imageFile.size);
      }
      
      console.log('Sending update request...');
      console.log('Update data JSON:', JSON.stringify(updateData));
      console.log('Image included:', !!imageFile);
      
      // Debug FormData contents to match Postman format
      console.log('FormData contents:');
      for (const [key, value] of formData.entries()) {
        if (value instanceof File) {
          console.log(key, '(File):', value.name, value.type, value.size);
        } else {
          console.log(key, ':', value);
        }
      }

      const baseUrl = import.meta.env.VITE_API_BASE_URL;
      const res = await fetch(`${baseUrl}/api/personnel/update-service/${service.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: token ? `Bearer ${token}` : '',
          // Let browser set Content-Type for FormData
        },
        body: formData,
      });

      if (!res.ok) {
        const errorData = await res.text();
        console.error('Update failed:', res.status, res.statusText, errorData);
        throw new Error(`Failed to update service: ${res.status} ${res.statusText}`);
      }

      const responseData = await res.json();
      console.log('Update successful:', responseData);
      console.log('Updated service data:', responseData.data);
      
      // Check both image fields in response
      if (responseData.data) {
        console.log('Response image field:', responseData.data.image);
        console.log('Response imageUrl field:', responseData.data.imageUrl);
      }
      
      onClose();
      onUpdated();
    } catch (err: any) {
      console.error('Service update error:', err);
      addToast('error', 'Failed to Update Service', err.message || 'There was an error updating the service. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };
  return (
    <div>
      <div className="mb-6">
        <p className="text-gray-600">Update the service information below. Changes will be reflected immediately.</p>
      </div>
      <form className="space-y-6" onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="md:col-span-2">
            <label htmlFor="edit-name" className="block text-sm font-semibold text-gray-700 mb-2">
              Service Name
            </label>
            <input 
              type="text" 
              id="edit-name" 
              className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 hover:border-gray-400" 
              value={name} 
              onChange={e => setName(e.target.value)} 
              required 
            />
          </div>
          <div className="md:col-span-2">
            <label htmlFor="edit-description" className="block text-sm font-semibold text-gray-700 mb-2">
              Description
            </label>
            <textarea 
              id="edit-description" 
              rows={4} 
              className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 hover:border-gray-400 resize-none" 
              value={description} 
              onChange={e => setDescription(e.target.value)} 
              required
            ></textarea>
          </div>
          <div>
            <label htmlFor="edit-price" className="block text-sm font-semibold text-gray-700 mb-2">
              Price (LKR)
            </label>
            <div className="relative">
              <DollarSignIcon size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
              <input 
                type="number" 
                id="edit-price" 
                className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 hover:border-gray-400" 
                value={price} 
                onChange={e => setPrice(Number(e.target.value))} 
                required 
              />
            </div>
          </div>
          <div>
            <label htmlFor="edit-discount" className="block text-sm font-semibold text-gray-700 mb-2">
              Discount (%)
            </label>
            <div className="relative">
              <PercentIcon size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
              <input 
                type="number" 
                id="edit-discount" 
                className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 hover:border-gray-400" 
                value={discount} 
                onChange={e => setDiscount(Number(e.target.value))} 
                min="0" 
                max="100" 
                required 
              />
            </div>
          </div>
          <div className="md:col-span-2">
            <label htmlFor="edit-image" className="block text-sm font-semibold text-gray-700 mb-2">
              Service Image
            </label>
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                {service.imageURL && !imageFile && (
                  <div className="relative">
                    <img src={service.imageURL} alt="Current" className="h-20 w-20 object-cover rounded-xl border-2 border-gray-200" />
                    <div className="absolute -top-2 -right-2 bg-green-500 text-white rounded-full p-1">
                      <ImageIcon size={12} />
                    </div>
                  </div>
                )}
                {imageFile && (
                  <div className="flex items-center space-x-3">
                    <div className="relative">
                      <img src={URL.createObjectURL(imageFile)} alt="New" className="h-20 w-20 object-cover rounded-xl border-2 border-blue-200" />
                      <div className="absolute -top-2 -right-2 bg-blue-500 text-white rounded-full p-1">
                        <ImageIcon size={12} />
                      </div>
                    </div>
                    <Button 
                      type="button" 
                      variant="outline" 
                      size="sm" 
                      onClick={handleRemoveImage}
                      className="hover:bg-red-50 hover:border-red-300 hover:text-red-600 transition-all duration-200"
                    >
                      Remove
                    </Button>
                  </div>
                )}
              </div>
              <input 
                type="file" 
                id="edit-image" 
                accept="image/*" 
                className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 hover:border-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100" 
                onChange={e => setImageFile(e.target.files ? e.target.files[0] : null)} 
              />
              <p className="text-xs text-gray-500">Leave blank to keep the current image.</p>
            </div>
          </div>
          <div className="md:col-span-2">
            <div className="flex items-center p-4 bg-green-50 rounded-xl border border-green-200">
              <input 
                id="edit-availability" 
                type="checkbox" 
                className="h-5 w-5 text-green-600 focus:ring-green-500 border-gray-300 rounded" 
                checked={availability} 
                onChange={e => setAvailability(e.target.checked)} 
              />
              <label htmlFor="edit-availability" className="ml-3 block text-sm font-medium text-green-800">
                Service is available for customers
              </label>
            </div>
          </div>
        </div>
        <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
          <Button 
            variant="outline" 
            onClick={onClose} 
            disabled={isSubmitting}
            className="px-6 py-3 hover:bg-gray-50 transition-all duration-200"
          >
            Cancel
          </Button>
          <Button 
            type="submit" 
            variant="primary" 
            disabled={isSubmitting}
            className="px-6 py-3 bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 shadow-lg hover:shadow-xl transition-all duration-200"
          >
            {isSubmitting ? 'Updating...' : 'Update Service'}
          </Button>
        </div>
      </form>
    </div>
  );
};
export default ServicesManager;