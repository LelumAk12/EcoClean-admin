import React from 'react';
import { motion } from 'framer-motion';
import { ArrowUpIcon, ArrowDownIcon } from 'lucide-react';
interface StatCardProps {
  title: string;
  value: string | number;
  icon: ReactNode;
  change?: number;
  changeLabel?: string;
  colorClass?: string;
}
const StatCard = ({
  title,
  value,
  icon,
  change,
  changeLabel = 'from last month',
  colorClass = 'bg-green-50 text-green-700'
}: StatCardProps) => {
  const isPositiveChange = change && change > 0;
  return <motion.div initial={{
    opacity: 0,
    y: 20
  }} animate={{
    opacity: 1,
    y: 0
  }} transition={{
    duration: 0.3
  }} className="bg-white rounded-lg shadow-sm border border-gray-100 p-5">
      <div className="flex justify-between">
        <div>
          <p className="text-sm text-gray-500 mb-1">{title}</p>
          <h3 className="text-2xl font-semibold text-gray-800">{value}</h3>
          {change !== undefined && <div className="flex items-center mt-2">
              <span className={`flex items-center text-xs ${isPositiveChange ? 'text-green-600' : 'text-red-600'}`}>
                {isPositiveChange ? <ArrowUpIcon size={14} className="mr-1" /> : <ArrowDownIcon size={14} className="mr-1" />}
                {Math.abs(change)}%
              </span>
              <span className="text-xs text-gray-500 ml-1">{changeLabel}</span>
            </div>}
        </div>
        <div className={`p-3 rounded-full ${colorClass}`}>{icon}</div>
      </div>
    </motion.div>;
};
export default StatCard;