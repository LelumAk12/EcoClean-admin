import React from 'react';
interface Column {
  header: string;
  accessor: string;
  cell?: (value: any, row: any) => ReactNode;
  className?: string;
}
interface TableProps {
  columns: Column[];
  data: any[];
  onRowClick?: (row: any) => void;
}
const Table = ({
  columns,
  data,
  onRowClick
}: TableProps) => {
  return <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr className="bg-gray-50">
            {columns.map((column, index) => <th key={index} className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b border-gray-200">
                {column.header}
              </th>)}
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {data.length > 0 ? data.map((row, rowIndex) => <tr key={rowIndex} className={`${onRowClick ? 'cursor-pointer hover:bg-gray-50' : ''}`} onClick={() => onRowClick && onRowClick(row)}>
                {columns.map((column, colIndex) => <td key={colIndex} className={`px-5 py-4 text-sm text-gray-700 ${column.className || ''}`}>
                    {column.cell ? column.cell(row[column.accessor], row) : row[column.accessor]}
                  </td>)}
              </tr>) : <tr>
              <td colSpan={columns.length} className="px-5 py-8 text-center text-sm text-gray-500">
                No data available
              </td>
            </tr>}
        </tbody>
      </table>
    </div>;
};
export default Table;