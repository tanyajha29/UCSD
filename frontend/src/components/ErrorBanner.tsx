import React from 'react';

interface Props {
  title?: string;
  message: string;
  onDismiss?: () => void;
}

export const ErrorBanner: React.FC<Props> = ({
  title = 'System Warning',
  message,
  onDismiss,
}) => {
  return (
    <div className="bg-rose-950/30 border border-rose-500/40 rounded-lg p-4 mb-4 text-rose-200 text-sm flex items-start justify-between">
      <div>
        <div className="font-semibold text-rose-400 mb-0.5">{title}</div>
        <div className="text-rose-200/90 text-xs font-mono">{message}</div>
      </div>
      {onDismiss && (
        <button
          onClick={onDismiss}
          className="text-rose-400 hover:text-rose-200 text-xs font-bold px-2 py-1"
        >
          ✕
        </button>
      )}
    </div>
  );
};
