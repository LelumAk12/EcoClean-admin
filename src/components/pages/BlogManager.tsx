/// <reference types="vite/client" />
import React, { useState, useEffect } from 'react';
import { SearchIcon, EditIcon, TrashIcon, EyeIcon, PlusIcon, XIcon, AlertCircleIcon, CheckCircleIcon, XCircleIcon, FileTextIcon, ClockIcon } from 'lucide-react';
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

interface Blog {
  id: string;
  title: string;
  content: string;
  author: string;
  createdAt: string;
  status: 'Published' | 'Draft';
  imageUrl?: string;
}

// Toast Notification Component
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

// Blog Card Component
const BlogCard = ({ blog, index, onView, onEdit, onDelete }: { 
  blog: Blog; 
  index: number; 
  onView: () => void; 
  onEdit: () => void;
  onDelete: () => void; 
}) => {
  const getStatusColor = () => {
    return blog.status === 'Published'
      ? 'bg-green-100 text-green-800 border-green-200'
      : 'bg-yellow-100 text-yellow-800 border-yellow-200';
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
            <div className="h-14 w-14 rounded-lg overflow-hidden bg-gradient-to-br from-gray-100 to-gray-200">
              {blog.imageUrl ? (
                <img 
                  className="h-full w-full object-cover" 
                  src={blog.imageUrl} 
                  alt={blog.title}
                  onError={(e) => {
                    e.currentTarget.style.display = 'none';
                    e.currentTarget.nextElementSibling?.classList.remove('hidden');
                  }}
                />
              ) : null}
              <div className={`h-full w-full flex items-center justify-center ${blog.imageUrl ? 'hidden' : ''}`}>
                <FileTextIcon size={24} className="text-gray-500" />
              </div>
            </div>
            <div className={`absolute -bottom-1 -right-1 h-4 w-4 rounded-full border-2 border-white ${blog.status === 'Published' ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-lg font-semibold text-gray-900 truncate group-hover:text-blue-600 transition-colors duration-200">
              {blog.title}
            </h3>
            <p className="text-sm text-gray-500 truncate">
              {blog.author}
            </p>
            <div className="flex items-center text-xs text-gray-400 mt-1">
              <span className="truncate">Created: {new Date(blog.createdAt).toLocaleDateString()}</span>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap gap-2 mb-4">
          <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getStatusColor()}`}>
            {blog.status}
          </span>
        </div>

        <div className="text-xs text-gray-500 mb-4 space-y-1">
          <div className="flex items-center">
            <FileTextIcon size={12} className="mr-2" />
            <span className="truncate">{blog.content.substring(0, 50)}...</span>
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

const BlogManager: React.FC = () => {
  const [blogs, setBlogs] = useState<Blog[]>([]);
  const [loading, setLoading] = useState(true);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [selectedBlog, setSelectedBlog] = useState<Blog | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [newBlog, setNewBlog] = useState({
    title: '',
    author: '',
    description: '',
    status: 'Published' as 'Published' | 'Draft',
    image: null as File | null
  });
  const [editBlog, setEditBlog] = useState({
    title: '',
    author: '',
    description: '',
    status: 'Published' as 'Published' | 'Draft',
    image: null as File | null
  });
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 6;

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
  const fetchBlogs = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${API_URL}/api/get-all-blogs`, {
        headers: {
          'Content-Type': 'application/json'
        }
      });
      if (response.data.success && Array.isArray(response.data.data)) {
        const mappedBlogs: Blog[] = response.data.data.map((item: any) => ({
          id: item._id,
          title: item.title,
          content: item.description,
          author: item.author,
          createdAt: item.createdAt,
          status: item.status,
          imageUrl: item.imageUrl
        }));
        setBlogs(mappedBlogs);
      } else {
        setBlogs([]);
        addToast('warning', 'No Blogs Found', 'No blog posts available.');
      }
    } catch (err: any) {
      addToast('error', 'Failed to Load Blogs', 'Unable to fetch blog data from the server.');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateBlog = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsSubmitting(true);
    try {
      const form = event.target as HTMLFormElement;
      const formData = new FormData();
      formData.append('blogData', JSON.stringify({
        title: newBlog.title,
        author: newBlog.author,
        description: newBlog.description,
        status: newBlog.status
      }));
      if (newBlog.image) {
        formData.append('image', newBlog.image);
      }
      const token = localStorage.getItem('authToken');
      await axios.post(`${API_URL}/api/personnel/create-blog`, formData, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      setIsAddModalOpen(false);
      setNewBlog({ title: '', author: '', description: '', status: 'Published', image: null });
      addToast('success', 'Blog Created', 'Blog post has been successfully created.');
      await fetchBlogs();
      form.reset();
    } catch (err: any) {
      addToast('error', 'Create Failed', err.response?.data?.message || 'Unable to create blog. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEditBlog = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedBlog) return;
    setIsSubmitting(true);
    try {
      const formData = new FormData();
      formData.append('blogData', JSON.stringify({
        title: editBlog.title,
        author: editBlog.author,
        description: editBlog.description,
        status: editBlog.status
      }));
      if (editBlog.image) {
        formData.append('image', editBlog.image);
      }
      const token = localStorage.getItem('authToken');
      await axios.patch(`${API_URL}/api/personnel/update-blog/${selectedBlog.id}`, formData, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setIsEditModalOpen(false);
      setSelectedBlog(null);
      addToast('success', 'Blog Updated', `${editBlog.title} has been successfully updated.`);
      await fetchBlogs();
    } catch (err: any) {
      addToast('error', 'Update Failed', err.response?.data?.message || 'Unable to update blog. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteBlog = async () => {
    if (!selectedBlog) return;
    setIsSubmitting(true);
    try {
      const token = localStorage.getItem('authToken');
      await axios.delete(`${API_URL}/api/personnel/delete-blog/${selectedBlog.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setIsDeleteModalOpen(false);
      setSelectedBlog(null);
      addToast('success', 'Blog Deleted', `${selectedBlog.title} has been successfully removed.`);
      await fetchBlogs();
    } catch (err: any) {
      addToast('error', 'Delete Failed', err.response?.data?.message || 'Unable to delete blog. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  useEffect(() => {
    fetchBlogs();
  }, []);

  const filteredBlogs = blogs.filter(blog =>
    (statusFilter === 'all' || blog.status === statusFilter) &&
    (blog.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
     blog.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
     blog.author.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  // Pagination logic
  const indexOfLastBlog = currentPage * itemsPerPage;
  const indexOfFirstBlog = indexOfLastBlog - itemsPerPage;
  const totalPages = Math.ceil(filteredBlogs.length / itemsPerPage);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-50 p-6">
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
                <FileTextIcon size={28} className="text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-indigo-900 to-purple-900 bg-clip-text text-transparent">
                  Blog Management
                </h1>
                <p className="text-gray-500 mt-1">Manage, publish, and edit blog posts for your platform</p>
              </div>
            </div>
            <Button 
              variant="primary" 
              icon={<PlusIcon size={18} />} 
              onClick={() => setIsAddModalOpen(true)}
              className="bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-600 hover:to-purple-700 shadow-lg hover:shadow-xl transition-all duration-200"
            >
              Create Blog
            </Button>
          </div>
        </motion.div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <motion.div 
            {...pageAnimations.statsCard(0)}
            className="relative bg-gradient-to-br from-blue-50 via-white to-blue-100 rounded-2xl shadow-lg border border-blue-100 p-6 hover:shadow-xl hover:scale-[1.02] transition-all duration-300 group overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-transparent to-indigo-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <div className="bg-gradient-to-br from-blue-500 to-indigo-600 p-3 rounded-xl shadow-lg">
                  <FileTextIcon size={24} className="text-white" />
                </div>
                <div className="text-right">
                  <div className="text-xs font-medium text-blue-600 bg-blue-100 px-2 py-1 rounded-full">
                    Total
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Total Blogs</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                  {blogs.length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-blue-500 to-indigo-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((blogs.length / Math.max(blogs.length, 10)) * 100, 100)}%` }}
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
                    Published
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Published</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-green-600 to-emerald-600 bg-clip-text text-transparent">
                  {blogs.filter(b => b.status === 'Published').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-green-500 to-emerald-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((blogs.filter(b => b.status === 'Published').length / Math.max(blogs.length, 1)) * 100, 100)}%` }}
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
                    Draft
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Draft</p>
                <p className="text-3xl font-bold bg-gradient-to-r from-yellow-600 to-orange-600 bg-clip-text text-transparent">
                  {blogs.filter(b => b.status === 'Draft').length}
                </p>
                <div className="w-full bg-gray-200 rounded-full h-2 mt-3">
                  <div 
                    className="bg-gradient-to-r from-yellow-500 to-orange-600 h-2 rounded-full transition-all duration-1000 ease-out"
                    style={{ width: `${Math.min((blogs.filter(b => b.status === 'Draft').length / Math.max(blogs.length, 1)) * 100, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Main Content Card */}
        <div className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden">
          <div className="p-6 border-b border-gray-200 bg-gradient-to-r from-gray-50 to-white">
            <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center space-y-4 lg:space-y-0">
              <div className="flex-1 max-w-md">
                <div className="relative">
                  <SearchIcon size={18} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                  <input 
                    type="text" 
                    placeholder="Search blogs by title, content, or author..." 
                    className="w-full pl-10 pr-4 py-3 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent bg-white shadow-sm hover:border-gray-300 transition-colors duration-200" 
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
                  <option value="Published">Published</option>
                  <option value="Draft">Draft</option>
                </select>
              </div>
            </div>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {loading ? (
                Array.from({ length: 6 }).map((_, index) => (
                  <div key={index} className="bg-white rounded-2xl shadow-lg border border-gray-100 overflow-hidden animate-pulse">
                    <div className="p-6">
                      <div className="flex items-center space-x-4 mb-4">
                        <div className="h-14 w-14 bg-gray-200 rounded-lg"></div>
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
                  {filteredBlogs.slice(indexOfFirstBlog, indexOfLastBlog).map((blog, index) => (
                    <BlogCard 
                      key={blog.id} 
                      blog={blog} 
                      index={index}
                      onView={() => {
                        setSelectedBlog(blog);
                        setIsViewModalOpen(true);
                      }}
                      onEdit={() => {
                        setSelectedBlog(blog);
                        setEditBlog({
                          title: blog.title,
                          author: blog.author,
                          description: blog.content,
                          status: blog.status,
                          image: null
                        });
                        setIsEditModalOpen(true);
                      }}
                      onDelete={() => {
                        setSelectedBlog(blog);
                        setIsDeleteModalOpen(true);
                      }}
                    />
                  ))}
                  {filteredBlogs.length === 0 && (
                    <div className="col-span-3 py-16 text-center">
                      <div className="bg-white rounded-2xl shadow-lg border border-gray-100 p-12">
                        <FileTextIcon size={64} className="mx-auto mb-6 text-gray-300" />
                        <h3 className="text-xl font-semibold text-gray-600 mb-2">
                          No blogs found
                        </h3>
                        <p className="text-gray-500">
                          No blogs match your current filter criteria. Try adjusting your filters or create a new blog.
                        </p>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>

            {!loading && filteredBlogs.length > 0 && (
              <div className="mt-6 pt-6 border-t border-gray-200">
                <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
                  <p className="text-sm text-gray-500">
                    Showing {indexOfFirstBlog + 1}-
                    {Math.min(indexOfLastBlog, filteredBlogs.length)} of{' '}
                    {filteredBlogs.length} blogs
                  </p>
                  <div className="flex space-x-2">
                    <Button 
                      variant="outline" 
                      size="sm" 
                      disabled={currentPage === 1} 
                      onClick={() => setCurrentPage(currentPage - 1)}
                      className="hover:bg-indigo-50 hover:border-indigo-200 hover:text-indigo-700"
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
                          ? "bg-gradient-to-r from-indigo-500 to-purple-600 text-white" 
                          : "hover:bg-indigo-50 hover:border-indigo-200 hover:text-indigo-700"
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
                      className="hover:bg-indigo-50 hover:border-indigo-200 hover:text-indigo-700"
                    >
                      Next
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Add Blog Modal */}
        <Modal isOpen={isAddModalOpen} onClose={() => setIsAddModalOpen(false)} title="Create New Blog">
          <form onSubmit={handleCreateBlog} className="space-y-4" encType="multipart/form-data">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label htmlFor="title" className="block text-sm font-medium text-gray-700 mb-1">Title *</label>
                <input type="text" name="title" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent" value={newBlog.title} onChange={e => setNewBlog({ ...newBlog, title: e.target.value })} required />
              </div>
              <div>
                <label htmlFor="author" className="block text-sm font-medium text-gray-700 mb-1">Author *</label>
                <input type="text" name="author" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent" value={newBlog.author} onChange={e => setNewBlog({ ...newBlog, author: e.target.value })} required />
              </div>
              <div className="md:col-span-2">
                <label htmlFor="description" className="block text-sm font-medium text-gray-700 mb-1">Description *</label>
                <textarea name="description" rows={4} className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent" value={newBlog.description} onChange={e => setNewBlog({ ...newBlog, description: e.target.value })} required></textarea>
              </div>
              <div>
                <label htmlFor="status" className="block text-sm font-medium text-gray-700 mb-1">Status *</label>
                <select name="status" className="admin-dropdown admin-dropdown-success w-full" value={newBlog.status} onChange={e => setNewBlog({ ...newBlog, status: e.target.value as 'Published' | 'Draft' })}>
                  <option value="Published">Published</option>
                  <option value="Draft">Draft</option>
                </select>
              </div>
              <div>
                <label htmlFor="image" className="block text-sm font-medium text-gray-700 mb-1">Image</label>
                <div className="relative w-full">
                  <input
                    id="blog-image-upload"
                    type="file"
                    accept="image/*"
                    className="hidden"
                    onChange={e => {
                      const file = e.target.files && e.target.files[0];
                      setNewBlog({ ...newBlog, image: file || null });
                    }}
                  />
                  <label htmlFor="blog-image-upload" className="flex flex-col items-center justify-center border-2 border-dashed border-indigo-300 rounded-xl bg-indigo-50 hover:bg-indigo-100 cursor-pointer transition-all duration-150 py-6 px-4 text-center">
                    {newBlog.image ? (
                      <>
                        <img src={URL.createObjectURL(newBlog.image)} alt="Preview" className="w-32 h-20 object-cover rounded-xl border-2 border-indigo-200 shadow mb-2" />
                        <span className="text-sm text-gray-700 font-medium">{newBlog.image.name}</span>
                        <button type="button" className="mt-2 text-xs text-red-500 underline" onClick={() => setNewBlog({ ...newBlog, image: null })}>Remove</button>
                        <span className="block text-xs text-gray-400 mt-1">Click to change image</span>
                      </>
                    ) : (
                      <>
                        <svg className="mx-auto mb-2 text-indigo-400" width="40" height="40" fill="none" viewBox="0 0 24 24"><path stroke="currentColor" strokeWidth="2" d="M12 16v-4m0 0V8m0 4h4m-4 0H8"/><rect width="18" height="14" x="3" y="5" rx="2" stroke="currentColor" strokeWidth="2"/></svg>
                        <span className="text-indigo-700 font-semibold">Drag & drop or click to choose image</span>
                        <span className="block text-xs text-gray-400 mt-1">PNG, JPG, JPEG up to 5MB</span>
                      </>
                    )}
                  </label>
                </div>
              </div>
            </div>
            <div className="flex justify-end space-x-3 pt-4">
              <Button variant="outline" type="button" onClick={() => setIsAddModalOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={isSubmitting}>
                {isSubmitting ? 'Creating...' : 'Create Blog'}
              </Button>
            </div>
          </form>
        </Modal>

        {/* View Blog Modal */}
        <Modal isOpen={isViewModalOpen} onClose={() => setIsViewModalOpen(false)} title="Blog Details">
          {selectedBlog && (
            <div className="space-y-6">
              <div className="flex items-center space-x-4 pb-4 border-b border-gray-200">
                <div className="h-16 w-16 rounded-lg overflow-hidden bg-gradient-to-br from-gray-100 to-gray-200">
                  {selectedBlog.imageUrl ? (
                    <img className="h-full w-full object-cover" src={selectedBlog.imageUrl} alt={selectedBlog.title} />
                  ) : (
                    <div className="h-full w-full flex items-center justify-center">
                      <FileTextIcon size={32} className="text-gray-500" />
                    </div>
                  )}
                </div>
                <div>
                  <h3 className="text-xl font-semibold text-gray-900">
                    {selectedBlog.title}
                  </h3>
                  <p className="text-gray-600">{selectedBlog.author}</p>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium mt-1 ${
                    selectedBlog.status === 'Published' 
                      ? 'bg-green-100 text-green-800' 
                      : 'bg-yellow-100 text-yellow-800'
                  }`}>
                    {selectedBlog.status}
                  </span>
                </div>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">Content</label>
                <p className="text-gray-900">{selectedBlog.content}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">Created At</label>
                <p className="text-gray-900">
                  {new Date(selectedBlog.createdAt).toLocaleDateString('en-US', { 
                    year: 'numeric', 
                    month: 'long', 
                    day: 'numeric' 
                  })}
                </p>
              </div>
              <div className="flex justify-end space-x-3 pt-4">
                <Button variant="outline" onClick={() => setIsViewModalOpen(false)}>
                  Close
                </Button>
                <Button variant="primary" onClick={() => {
                  setIsViewModalOpen(false);
                  setIsEditModalOpen(true);
                }}>
                  Edit Blog
                </Button>
              </div>
            </div>
          )}
        </Modal>

        {/* Edit Blog Modal */}
        <Modal isOpen={isEditModalOpen} onClose={() => setIsEditModalOpen(false)} title="Edit Blog">
          {selectedBlog && (
            <form onSubmit={handleEditBlog} className="space-y-4" encType="multipart/form-data">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="edit-title" className="block text-sm font-medium text-gray-700 mb-1">Title *</label>
                  <input type="text" name="title" id="edit-title" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" value={editBlog.title} onChange={e => setEditBlog({ ...editBlog, title: e.target.value })} required />
                </div>
                <div>
                  <label htmlFor="edit-author" className="block text-sm font-medium text-gray-700 mb-1">Author *</label>
                  <input type="text" name="author" id="edit-author" className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" value={editBlog.author} onChange={e => setEditBlog({ ...editBlog, author: e.target.value })} required />
                </div>
                <div className="md:col-span-2">
                  <label htmlFor="edit-description" className="block text-sm font-medium text-gray-700 mb-1">Description *</label>
                  <textarea name="description" id="edit-description" rows={4} className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" value={editBlog.description} onChange={e => setEditBlog({ ...editBlog, description: e.target.value })} required></textarea>
                </div>
                <div>
                  <label htmlFor="edit-status" className="block text-sm font-medium text-gray-700 mb-1">Status *</label>
                  <select name="status" id="edit-status" className="admin-dropdown admin-dropdown-success w-full" value={editBlog.status} onChange={e => setEditBlog({ ...editBlog, status: e.target.value as 'Published' | 'Draft' })}>
                    <option value="Published">Published</option>
                    <option value="Draft">Draft</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="edit-image" className="block text-sm font-medium text-gray-700 mb-1">Image</label>
                  <div className="relative w-full">
                    <input
                      id="edit-blog-image-upload"
                      type="file"
                      accept="image/*"
                      className="hidden"
                      onChange={e => {
                        const file = e.target.files && e.target.files[0];
                        setEditBlog({ ...editBlog, image: file || null });
                      }}
                    />
                    <label htmlFor="edit-blog-image-upload" className="flex flex-col items-center justify-center border-2 border-dashed border-green-300 rounded-xl bg-green-50 hover:bg-green-100 cursor-pointer transition-all duration-150 py-6 px-4 text-center">
                      {editBlog.image ? (
                        <>
                          <img src={URL.createObjectURL(editBlog.image)} alt="Preview" className="w-32 h-20 object-cover rounded-xl border-2 border-green-200 shadow mb-2" />
                          <span className="text-sm text-gray-700 font-medium">{editBlog.image.name}</span>
                          <button type="button" className="mt-2 text-xs text-red-500 underline" onClick={() => setEditBlog({ ...editBlog, image: null })}>Remove</button>
                          <span className="block text-xs text-gray-400 mt-1">Click to change image</span>
                        </>
                      ) : (
                        <>
                          <img src={selectedBlog.imageUrl || 'https://via.placeholder.com/80x60?text=No+Image'} alt="Current" className="w-32 h-20 object-cover rounded-xl border-2 border-green-200 shadow mb-2" />
                          <span className="text-green-700 font-semibold">Drag & drop or click to choose new image</span>
                          <span className="block text-xs text-gray-400 mt-1">PNG, JPG, JPEG up to 5MB</span>
                        </>
                      )}
                    </label>
                  </div>
                </div>
              </div>
              <div className="flex justify-end space-x-3 pt-4">
                <Button variant="outline" type="button" onClick={() => setIsEditModalOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit" variant="primary" disabled={isSubmitting}>
                  {isSubmitting ? 'Updating...' : 'Update Blog'}
                </Button>
              </div>
            </form>
          )}
        </Modal>

        {/* Delete Confirmation Modal */}
        <Modal isOpen={isDeleteModalOpen} onClose={() => setIsDeleteModalOpen(false)} title="Delete Blog">
          {selectedBlog && (
            <div>
              <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-4">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <AlertCircleIcon className="h-5 w-5 text-red-400" />
                  </div>
                  <div className="ml-3">
                    <p className="text-sm text-red-700">
                      This action cannot be undone. This will permanently delete
                      the blog post and remove all associated data.
                    </p>
                  </div>
                </div>
              </div>
              <p className="text-gray-600">
                Are you sure you want to delete the blog post{' '}
                <span className="font-medium">{selectedBlog.title}</span>?
              </p>
              <div className="mt-4 bg-gray-50 p-4 rounded-md">
                <h4 className="text-sm font-medium text-gray-700 mb-2">
                  Blog Information
                </h4>
                <ul className="text-sm text-gray-600 space-y-1">
                  <li>
                    <span className="font-medium">Title:</span> {selectedBlog.title}
                  </li>
                  <li>
                    <span className="font-medium">Author:</span> {selectedBlog.author}
                  </li>
                  <li>
                    <span className="font-medium">Status:</span> {selectedBlog.status}
                  </li>
                </ul>
              </div>
              <div className="flex justify-end space-x-3 mt-6">
                <Button variant="outline" onClick={() => setIsDeleteModalOpen(false)}>
                  Cancel
                </Button>
                <Button variant="danger" onClick={handleDeleteBlog} disabled={isSubmitting}>
                  {isSubmitting ? 'Deleting...' : 'Delete Blog'}
                </Button>
              </div>
            </div>
          )}
        </Modal>
      </div>
    </div>
  );
};

export default BlogManager;