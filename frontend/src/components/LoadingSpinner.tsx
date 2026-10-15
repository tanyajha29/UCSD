import React from 'react';

interface Props {
  message?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const LoadingSpinner: React.FC<Props> = ({ message = 'Processing...', size = 'md' }) => {
  const sizeClasses = {
    sm: 'w-4 h-4 border-2',
    md: 'w-6 h-6 border-2',
    lg: 'w-10 h-10 border-3',
  }[size];

  return (
    <div className="flex flex-col items-center justify-center p-6 space-y-3">
      <div
        className={`${sizeClasses} border-cyan-500/20 border-t-cyan-400 rounded-full animate-spin`}
      />
      {message && <p className="text-xs text-slate-400 font-mono tracking-wide">{message}</p>}
    </div>
  );
};
