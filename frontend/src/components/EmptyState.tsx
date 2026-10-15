import React from 'react';

interface Props {
  title: string;
  description: string;
  actionText?: string;
  onAction?: () => void;
  icon?: React.ReactNode;
}

export const EmptyState: React.FC<Props> = ({
  title,
  description,
  actionText,
  onAction,
  icon,
}) => {
  return (
    <div className="bg-cyber-card border border-cyber-border rounded-lg p-10 text-center flex flex-col items-center justify-center">
      {icon && <div className="text-slate-500 mb-3">{icon}</div>}
      <h3 className="text-base font-semibold text-slate-200 mb-1">{title}</h3>
      <p className="text-sm text-slate-400 max-w-md mb-5">{description}</p>
      {actionText && onAction && (
        <button
          onClick={onAction}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
        >
          {actionText}
        </button>
      )}
    </div>
  );
};
