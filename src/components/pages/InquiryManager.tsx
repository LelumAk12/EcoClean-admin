/// <reference types="vite/client" />
import React, { useState, useEffect } from 'react';
import { SearchIcon, FilterIcon, TrashIcon, MessageCircleIcon, CheckCircleIcon, XCircleIcon, CalendarIcon, EyeIcon, MessageSquareIcon, AlertCircleIcon, TagIcon } from 'lucide-react';
import { motion } from 'framer-motion';
import Card from '../common/Card';
import Button from '../common/Button';
import Table from '../common/Table';
import Modal from '../common/Modal';
import { pageAnimations } from '../../utils/animations';
interface Inquiry {
  id: string;
  userId: string;
  subject: string;
  message: string;
  repliedMessage?: string | null;
  category: string;
  status: 'Pending' | 'Replied';
  createdAt: string;
  updatedAt: string;
}
const InquiryManager = () => {
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [isReplyModalOpen, setIsReplyModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [selectedInquiry, setSelectedInquiry] = useState<Inquiry | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [replyMessage, setReplyMessage] = useState('');
  const [inquiries, setInquiries] = useState<Inquiry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const categories = ['General', 'Services', 'Billing', 'Complaint', 'Suggestions', 'Feedback'];

  // Fetch inquiries from API
  useEffect(() => {
    const fetchInquiries = async () => {
      setLoading(true);
      setError(null);
      try {
        const token = localStorage.getItem('authToken');
        if (!token) throw new Error('No authentication token available');
        const baseUrl = import.meta.env.VITE_API_BASE_URL;
        const response = await fetch(`${baseUrl}/api/personnel/get-All-inquries-personnel`, {
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        });
        const data = await response.json();
        if (data.success && Array.isArray(data.data)) {
          setInquiries(
            data.data.map((inq: any) => ({
              id: inq._id,
              userId: inq.userId,
              subject: inq.subject,
              message: inq.message,
              repliedMessage: inq.Repliedmessage,
              category: inq.category,
              status: inq.status,
              createdAt: inq.createdAt,
              updatedAt: inq.updatedAt,
            }))
          );
        } else {
          setInquiries([]);
          setError(data.message || 'No inquiries found');
        }
      } catch (err: any) {
        setError(err.message || 'Failed to fetch inquiries');
        setInquiries([]);
      } finally {
        setLoading(false);
      }
    };
    fetchInquiries();
  }, []);
  const columns = [
    {
      header: 'Subject',
      accessor: 'subject',
      cell: (value: string) => <div className="font-medium text-gray-900">{value}</div>
    },
    {
      header: 'Message',
      accessor: 'message',
      cell: (value: string) => <div className="text-gray-500 text-sm truncate max-w-xs">{value?.substring(0, 60)}...</div>
    },
    {
      header: 'Reply',
      accessor: 'repliedMessage',
      cell: (value: string | null | undefined) => value ? <div className="text-green-600 text-sm truncate max-w-xs">{value?.substring(0, 60)}...</div> : <span className="text-gray-400 text-sm italic">Not replied yet</span>
    },
    {
      header: 'Category',
      accessor: 'category',
      cell: (value: string) => <div className="flex items-center"><TagIcon size={14} className="mr-1 text-gray-400" /><span>{value}</span></div>
    },
    {
      header: 'Status',
      accessor: 'status',
      cell: (value: string) => <span className={`px-2 py-1 text-xs font-medium rounded-full ${value === 'Pending' ? 'bg-blue-100 text-blue-800' : value === 'Replied' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>{value}</span>
    },
    {
      header: 'Actions',
      accessor: 'id',
      cell: (_: string, row: Inquiry) => <div className="flex space-x-2">
        <Button variant="outline" size="sm" icon={<EyeIcon size={14} />} onClick={e => {
          e.stopPropagation();
          setSelectedInquiry(row);
          setIsViewModalOpen(true);
        }}>View</Button>
        <Button variant="primary" size="sm" icon={<MessageSquareIcon size={14} />} onClick={e => {
          e.stopPropagation();
          setSelectedInquiry(row);
          setReplyMessage(row.repliedMessage || '');
          setIsReplyModalOpen(true);
        }}>Reply</Button>
        <Button variant="danger" size="sm" icon={<TrashIcon size={14} />} onClick={e => {
          e.stopPropagation();
          setSelectedInquiry(row);
          setIsDeleteModalOpen(true);
        }}>Delete</Button>
      </div>
    }
  ];
  const filteredInquiries = inquiries.filter(inquiry =>
    (statusFilter === 'all' || inquiry.status === statusFilter) &&
    (categoryFilter === 'all' || inquiry.category === categoryFilter) &&
    (inquiry.subject.toLowerCase().includes(searchTerm.toLowerCase()) || inquiry.message.toLowerCase().includes(searchTerm.toLowerCase()))
  );
  
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-green-50 to-emerald-50 p-6">
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Enhanced Header */}
        <motion.div 
          {...pageAnimations.header}
          className="bg-white rounded-2xl shadow-xl border border-gray-100 p-8"
        >
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
            {/* Title Section */}
            <div className="flex items-center">
              <div className="p-3 bg-gradient-to-r from-green-500 to-emerald-600 rounded-xl mr-4">
                <MessageCircleIcon size={28} className="text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-green-900 to-emerald-900 bg-clip-text text-transparent">
                  Customer Inquiry Management
                </h1>
                <p className="text-gray-600 mt-2 text-lg">
                  Manage and respond to customer inquiries and feedback
                </p>
              </div>
            </div>
            
            {/* Status Badges - Right Side */}
            <div className="flex items-center space-x-3">
              <div className="flex items-center space-x-1 px-4 py-2 bg-blue-50 text-blue-700 rounded-xl border border-blue-200">
                <span className="text-sm font-medium">
                  Pending: {inquiries.filter(i => i.status === 'Pending').length}
                </span>
              </div>
              <div className="flex items-center space-x-1 px-4 py-2 bg-green-50 text-green-700 rounded-xl border border-green-200">
                <span className="text-sm font-medium">
                  Replied: {inquiries.filter(i => i.status === 'Replied').length}
                </span>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <motion.div 
            {...pageAnimations.statsCard(0)}
            className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-xl transition-all duration-300 hover:-translate-y-1"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Total Inquiries</p>
                <p className="text-3xl font-bold text-gray-900">{inquiries.length}</p>
              </div>
              <div className="p-3 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl">
                <MessageCircleIcon size={24} className="text-white" />
              </div>
            </div>
          </motion.div>
          <motion.div 
            {...pageAnimations.statsCard(1)}
            className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-xl transition-all duration-300 hover:-translate-y-1"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Pending</p>
                <p className="text-3xl font-bold text-blue-600">{inquiries.filter(i => i.status === 'Pending').length}</p>
              </div>
              <div className="p-3 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl">
                <AlertCircleIcon size={24} className="text-white" />
              </div>
            </div>
          </motion.div>
          <motion.div 
            {...pageAnimations.statsCard(2)}
            className="bg-white rounded-2xl shadow-lg border border-gray-100 p-6 hover:shadow-xl transition-all duration-300 hover:-translate-y-1"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-1">Replied</p>
                <p className="text-3xl font-bold text-green-600">{inquiries.filter(i => i.status === 'Replied').length}</p>
              </div>
              <div className="p-3 bg-gradient-to-br from-green-500 to-emerald-600 rounded-xl">
                <CheckCircleIcon size={24} className="text-white" />
              </div>
            </div>
          </motion.div>
        </div>

        {/* Search and Filters - Unified in a single row */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Search Input */}
            <div className="relative">
              <input 
                type="text" 
                placeholder="Search inquiries..." 
                className="pl-10 pr-4 py-3 border border-gray-200 rounded-lg w-full focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200"
                value={searchTerm} 
                onChange={e => setSearchTerm(e.target.value)} 
              />
              <SearchIcon size={18} className="absolute left-3 top-3.5 text-gray-400" />
            </div>
            
            {/* Category Filter */}
            <div className="relative">
              <select 
                value={categoryFilter} 
                onChange={e => setCategoryFilter(e.target.value)} 
                className="w-full py-3 px-4 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200 bg-white"
              >
                <option value="all">All Categories</option>
                {categories.map(category => 
                  <option key={category} value={category}>{category}</option>
                )}
              </select>
            </div>
            
            {/* Status Filter */}
            <div className="relative">
              <select 
                value={statusFilter} 
                onChange={e => setStatusFilter(e.target.value)} 
                className="w-full py-3 px-4 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent transition-all duration-200 bg-white"
              >
                <option value="all">All Statuses</option>
                <option value="Pending">Pending</option>
                <option value="Replied">Replied</option>
              </select>
            </div>
            
            {/* More Filters Button */}
            <div className="flex justify-start">
              <Button variant="outline" icon={<FilterIcon size={18} />} className="px-6 py-3">
                More Filters
              </Button>
            </div>
          </div>
        </div>

        <div className="space-y-6">
      <Card>
        {loading ? (
          <div className="py-16 text-center">
            <div className="flex justify-center mb-4">
              <div className="animate-spin rounded-full h-12 w-12 border-4 border-green-500 border-t-transparent"></div>
            </div>
            <p className="text-gray-600 text-lg font-medium">Loading inquiries...</p>
            <p className="text-gray-400 text-sm mt-1">Please wait while we fetch your data</p>
          </div>
        ) : error ? (
          <div className="py-16 text-center text-red-500">
            <div className="flex justify-center mb-4">
              <div className="p-4 bg-red-100 rounded-full">
                <XCircleIcon size={32} className="text-red-500" />
              </div>
            </div>
            <p className="text-lg font-medium">{error}</p>
          </div>
        ) : (
          <>
            <Table columns={columns} data={filteredInquiries} onRowClick={row => {
              setSelectedInquiry(row);
              setIsViewModalOpen(true);
            }} />
            <div className="mt-4 flex justify-between items-center">
              <p className="text-sm text-gray-500">
                Showing {filteredInquiries.length} of {inquiries.length} inquiries
              </p>
              <div className="flex space-x-2">
                <Button variant="outline" size="sm">
                  Previous
                </Button>
                <Button variant="outline" size="sm" className="bg-green-50">
                  1
                </Button>
                <Button variant="outline" size="sm">
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </Card>
      {/* View Inquiry Modal */}
      <Modal isOpen={isViewModalOpen} onClose={() => setIsViewModalOpen(false)} title="Inquiry Details" size="lg">
        {selectedInquiry && (
          <div className="space-y-6">
            <div className="flex flex-col items-center justify-center mb-2">
              <div className="flex items-center gap-3 mb-2">
                <span className={`px-3 py-1 text-sm font-semibold rounded-full shadow-sm ${selectedInquiry.status === 'Pending' ? 'bg-blue-100 text-blue-800 border border-blue-200' : 'bg-green-100 text-green-800 border border-green-200'}`}>
                  {selectedInquiry.status}
                </span>
                <span className="flex items-center text-gray-500 text-sm">
                  <CalendarIcon size={16} className="mr-1" />
                  {new Date(selectedInquiry.createdAt).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' })}
                </span>
                <span className="flex items-center text-gray-500 text-sm">
                  <TagIcon size={16} className="mr-1" />
                  {selectedInquiry.category}
                </span>
              </div>
              <h2 className="text-2xl font-bold text-gray-900 text-center mb-1">{selectedInquiry.subject}</h2>
            </div>

            <div className="bg-white rounded-xl shadow border border-gray-100 p-6">
              <h4 className="font-semibold text-lg text-gray-800 mb-2">Customer Message</h4>
              <div className="p-4 bg-gray-50 rounded-lg border border-gray-100">
                <p className="text-gray-700 whitespace-pre-line text-base leading-relaxed">
                  {selectedInquiry.message}
                </p>
              </div>
            </div>

            {selectedInquiry.repliedMessage && (
              <div className="bg-green-50 rounded-xl shadow border border-green-100 p-6">
                <h4 className="font-semibold text-lg text-green-800 mb-2">Reply</h4>
                <div className="p-4 bg-white rounded-lg border border-green-100">
                  <p className="text-gray-700 whitespace-pre-line text-base leading-relaxed">
                    {selectedInquiry.repliedMessage}
                  </p>
                </div>
              </div>
            )}

            <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
              <Button variant="outline" onClick={() => setIsViewModalOpen(false)} className="px-6 py-2.5 text-gray-700 border-gray-300 hover:bg-gray-50 shadow-sm">
                Close
              </Button>
              <Button variant="primary" icon={<MessageCircleIcon size={18} />} onClick={() => {
                setIsViewModalOpen(false);
                setReplyMessage(selectedInquiry.repliedMessage || '');
                setIsReplyModalOpen(true);
              }} className="px-6 py-2.5 bg-green-600 hover:bg-green-700 text-white shadow-sm">
                Reply to Inquiry
              </Button>
            </div>
          </div>
        )}
      </Modal>
      {/* Reply Modal */}
      <Modal isOpen={isReplyModalOpen} onClose={() => setIsReplyModalOpen(false)} title="Reply to Inquiry" size="lg">
        {selectedInquiry && <form className="space-y-4" onSubmit={async (e) => {
            e.preventDefault();
            if (!selectedInquiry) return;
            try {
              setLoading(true);
              const token = localStorage.getItem('authToken');
              if (!token) throw new Error('No authentication token available');
              const baseUrl = import.meta.env.VITE_API_BASE_URL;
              const response = await fetch(`${baseUrl}/api/personnel/update-inquiry/${selectedInquiry.id}`, {
                method: 'PATCH',
                headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  UpdatedCustomerInquiry: {
                    Repliedmessage: replyMessage,
                    status: 'Replied',
                  }
                })
              });
              const data = await response.json();
              if (data.success) {
                setInquiries(prev => prev.map(inq =>
                  inq.id === selectedInquiry.id
                    ? { ...inq, repliedMessage: replyMessage, status: 'Replied' }
                    : inq
                ));
                setIsReplyModalOpen(false);
              } else {
                setError(data.message || 'Failed to update inquiry');
              }
            } catch (err: any) {
              setError(err.message || 'Failed to update inquiry');
            } finally {
              setLoading(false);
            }
          }}>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Subject
              </label>
              <div className="flex items-center px-3 py-2 border border-gray-300 rounded-md bg-gray-50">
                <span>Re: {selectedInquiry.subject}</span>
              </div>
            </div>
            <div>
              <label htmlFor="reply-message" className="block text-sm font-medium text-gray-700 mb-1">
                Message
              </label>
              <textarea id="reply-message" rows={8} className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="Type your reply here..." value={replyMessage || `Dear User,\n\nThank you for contacting EcoClean regarding your inquiry about \"${selectedInquiry.subject}\".\n\n\n\nBest regards,\nCustomer Support Team\nEcoClean Waste Management`} onChange={e => setReplyMessage(e.target.value)}></textarea>
            </div>
            <div className="flex justify-end space-x-3 pt-4">
              <Button variant="outline" onClick={() => setIsReplyModalOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" icon={<MessageCircleIcon size={18} />}>
                Send Reply
              </Button>
            </div>
          </form>}
      </Modal>
      {/* Delete Confirmation Modal */}
      <Modal isOpen={isDeleteModalOpen} onClose={() => setIsDeleteModalOpen(false)} title="Delete Inquiry">
        {selectedInquiry && <div>
            <p className="text-gray-600">
              Are you sure you want to delete the inquiry "
              {selectedInquiry.subject}"?
              This action cannot be undone.
            </p>
            <div className="flex justify-end space-x-3 mt-6">
              <Button variant="outline" onClick={() => setIsDeleteModalOpen(false)}>
                Cancel
              </Button>
              <Button variant="danger" onClick={async () => {
                if (!selectedInquiry) return;
                try {
                  setLoading(true);
                  const token = localStorage.getItem('authToken');
                  if (!token) throw new Error('No authentication token available');
                  const baseUrl = import.meta.env.VITE_API_BASE_URL;
                  const response = await fetch(`${baseUrl}/api/personnel/delete-inquiry/${selectedInquiry.id}`, {
                    method: 'DELETE',
                    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                  });
                  const data = await response.json();
                  if (data.success) {
                    setInquiries(prev => prev.filter(inq => inq.id !== selectedInquiry.id));
                  } else {
                    setError(data.message || 'Failed to delete inquiry');
                  }
                } catch (err: any) {
                  setError(err.message || 'Failed to delete inquiry');
                } finally {
                  setIsDeleteModalOpen(false);
                  setLoading(false);
                }
              }}>
                Delete
              </Button>
            </div>
          </div>}
      </Modal>
        </div>
      </div>
    </div>
  );
};

export default InquiryManager;