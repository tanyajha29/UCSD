import React from 'react';
import { WorkbenchPage } from './WorkbenchPage';

interface ResultsPageProps {
  analysisId: string;
  onBack?: () => void;
  [key: string]: any;
}

export const ResultsPage: React.FC<ResultsPageProps> = ({ analysisId, onBack, ...rest }) => {
  return (
    <WorkbenchPage
      analysisId={analysisId}
      {...rest}
    />
  );
};

export default ResultsPage;
