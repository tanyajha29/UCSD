import React from 'react';
import { IntakePage } from './IntakePage';

export const AnalyzePage: React.FC<any> = (props) => {
  return (
    <IntakePage
      onAnalysisComplete={props.onAnalysisComplete || (() => {})}
      onNavigateTab={props.onNavigateTab || (() => {})}
      {...props}
    />
  );
};

export default AnalyzePage;
