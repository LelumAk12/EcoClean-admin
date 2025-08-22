import React from 'react';
import { motion } from 'framer-motion';
interface CardProps {
  title?: string;
  icon?: ReactNode;
  className?: string;
  children: ReactNode;
}
const Card = ({
  title,
  icon,
  className = '',
  children
}: CardProps) => {
  return <motion.div initial={{
    opacity: 0,
    y: 20
  }} animate={{
    opacity: 1,
    y: 0
  }} transition={{
    duration: 0.3
  }} className={`bg-white rounded-lg shadow-sm border border-gray-100 overflow-hidden ${className}`}>
      {(title || icon) && <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
          {title && <h3 className="font-medium text-gray-700">{title}</h3>}
          {icon && <div className="text-gray-500">{icon}</div>}
        </div>}
      <div className="p-5">{children}</div>
    </motion.div>;
};
export default Card;