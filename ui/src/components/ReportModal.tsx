/*
ui/src/components/ReportModal.tsx
Interactive modal dialog rendering structured remediation report and raw markdown.
*/

import React, { useState } from 'react';

interface ReportModalProps {
  runId: string;
  markdown: string;
  onClose: () => void;
}

export const ReportModal: React.FC<ReportModalProps> = ({ runId, markdown, onClose }) => {
  const [activeTab, setActiveTab] = useState<'rendered' | 'raw'>('rendered');
  const [copied, setCopied] = useState<boolean>(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `report_${runId}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Custom parser to render GitHub Flavored Markdown cleanly
  const renderMarkdownContent = (content: string) => {
    if (!content.trim()) {
      return (
        <div className="p-8 text-center text-slate-400">
          <p>No report content available for run {runId}.</p>
        </div>
      );
    }

    const lines = content.split('\n');
    const elements: React.ReactNode[] = [];
    let inTable = false;
    let tableHeaders: string[] = [];
    let tableRows: string[][] = [];
    let inAlert = false;
    let alertType = 'note';
    let alertLines: string[] = [];

    const flushTable = (keyPrefix: string) => {
      if (inTable && tableHeaders.length > 0) {
        elements.push(
          <div key={`table-${keyPrefix}`} className="my-4 overflow-x-auto rounded-lg border border-slate-200">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-slate-50 text-slate-700 font-semibold border-b border-slate-200">
                <tr>
                  {tableHeaders.map((th, idx) => (
                    <th key={idx} className="px-3.5 py-2.5 whitespace-nowrap">
                      {th.replace(/\*\*/g, '')}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {tableRows.map((row, rIdx) => (
                  <tr key={rIdx} className="hover:bg-slate-50/80 transition-colors">
                    {row.map((cell, cIdx) => (
                      <td key={cIdx} className="px-3.5 py-2 text-slate-800">
                        {cell.includes('`') ? (
                          <span className="bg-slate-100 text-sky-800 px-1 py-0.5 rounded text-[11px]">
                            {cell.replace(/`/g, '')}
                          </span>
                        ) : (
                          cell.replace(/\*\*/g, '')
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
        inTable = false;
        tableHeaders = [];
        tableRows = [];
      }
    };

    const flushAlert = (keyPrefix: string) => {
      if (inAlert && alertLines.length > 0) {
        const isWarning = alertType.includes('warning') || alertType.includes('caution');
        const bgCls = isWarning ? 'bg-amber-50 border-amber-300 text-amber-950' : 'bg-sky-50 border-sky-300 text-sky-950';
        elements.push(
          <div key={`alert-${keyPrefix}`} className={`my-4 p-4 rounded-xl border ${bgCls} text-xs shadow-xs space-y-1.5`}>
            {alertLines.map((al, idx) => (
              <div key={idx} className={idx === 0 ? 'font-bold text-sm flex items-center gap-1.5' : 'text-slate-800'}>
                {al}
              </div>
            ))}
          </div>
        );
        inAlert = false;
        alertLines = [];
      }
    };

    lines.forEach((line, idx) => {
      const trimmed = line.trim();

      // Check for Callout Alerts like > [!WARNING]
      if (trimmed.startsWith('> [!')) {
        flushTable(`flush-tbl-${idx}`);
        inAlert = true;
        alertType = trimmed.toLowerCase();
        alertLines = [];
        return;
      }
      if (inAlert && trimmed.startsWith('>')) {
        const text = trimmed.replace(/^>\s*/, '');
        if (text) alertLines.push(text);
        return;
      }
      if (inAlert && !trimmed.startsWith('>')) {
        flushAlert(`flush-alert-${idx}`);
      }

      // Check Table Rows
      if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
        const cells = trimmed
          .slice(1, -1)
          .split('|')
          .map((c) => c.trim());
        // Skip separator row like |---|---|
        if (cells.every((c) => /^[-:]+$/.test(c))) {
          return;
        }
        if (!inTable) {
          inTable = true;
          tableHeaders = cells;
          tableRows = [];
        } else {
          tableRows.push(cells);
        }
        return;
      } else {
        flushTable(`flush-table-${idx}`);
      }

      // Headers
      if (trimmed.startsWith('# ')) {
        elements.push(
          <h1 key={idx} className="text-xl font-bold text-slate-900 mt-4 mb-2 flex items-center gap-2">
            {trimmed.replace('# ', '')}
          </h1>
        );
      } else if (trimmed.startsWith('## ')) {
        elements.push(
          <h2 key={idx} className="text-base font-bold text-slate-900 mt-5 mb-2 pb-1 border-b border-slate-200">
            {trimmed.replace('## ', '')}
          </h2>
        );
      } else if (trimmed.startsWith('### ')) {
        elements.push(
          <h3 key={idx} className="text-sm font-semibold text-slate-800 mt-4 mb-1">
            {trimmed.replace('### ', '')}
          </h3>
        );
      } else if (trimmed.startsWith('#### ')) {
        elements.push(
          <h4 key={idx} className="text-xs font-semibold text-slate-600 mt-3 mb-1 uppercase tracking-wider">
            {trimmed.replace('#### ', '')}
          </h4>
        );
      }
      // List items
      else if (trimmed.startsWith('- ') || trimmed.startsWith('• ') || trimmed.startsWith('* ')) {
        const itemText = trimmed.replace(/^[-•*]\s*/, '');
        elements.push(
          <div key={idx} className="flex items-start gap-2 text-xs text-slate-700 my-1 ml-2">
            <span className="text-sky-500 font-bold mt-0.5">•</span>
            <span className="flex-1 leading-relaxed">
              {itemText.includes('`') ? (
                itemText.split('`').map((part, pIdx) =>
                  pIdx % 2 === 1 ? (
                    <code key={pIdx} className="bg-slate-100 text-slate-800 font-mono px-1 py-0.5 rounded text-[11px]">
                      {part}
                    </code>
                  ) : (
                    part
                  )
                )
              ) : (
                itemText
              )}
            </span>
          </div>
        );
      }
      // Blockquotes
      else if (trimmed.startsWith('>')) {
        const bText = trimmed.replace(/^>\s*/, '');
        elements.push(
          <blockquote key={idx} className="border-l-3 border-sky-400 bg-sky-50/50 pl-3 py-1 my-1 text-xs text-slate-700 italic">
            {bText}
          </blockquote>
        );
      }
      // Horizontal Rule
      else if (trimmed === '---') {
        elements.push(<hr key={idx} className="border-slate-200 my-4" />);
      }
      // Regular paragraph
      else if (trimmed) {
        elements.push(
          <p key={idx} className="text-xs text-slate-600 my-1 leading-relaxed">
            {trimmed.includes('`') ? (
              trimmed.split('`').map((part, pIdx) =>
                pIdx % 2 === 1 ? (
                  <code key={pIdx} className="bg-slate-100 text-slate-800 font-mono px-1 py-0.5 rounded text-[11px]">
                    {part}
                  </code>
                ) : (
                  part
                )
              )
            ) : (
              trimmed
            )}
          </p>
        );
      }
    });

    flushTable('end');
    flushAlert('end');

    return elements;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden">
        {/* Header Bar */}
        <div className="px-6 py-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-2xl">📄</span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900">Remediation Report</h3>
                <span className="font-mono text-xs font-semibold px-2 py-0.5 bg-slate-200/80 text-slate-700 rounded-md">
                  {runId}
                </span>
              </div>
              <p className="text-xs text-slate-500">Autonomous remediation findings, policy checks, diffs, and verification summary.</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* View Mode Toggle */}
            <div className="flex bg-slate-200/70 p-0.5 rounded-lg border border-slate-300/60 text-xs">
              <button
                onClick={() => setActiveTab('rendered')}
                className={`px-3 py-1 rounded-md font-medium transition-all cursor-pointer ${
                  activeTab === 'rendered' ? 'bg-white text-slate-900 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Rendered View
              </button>
              <button
                onClick={() => setActiveTab('raw')}
                className={`px-3 py-1 rounded-md font-medium transition-all cursor-pointer ${
                  activeTab === 'raw' ? 'bg-white text-slate-900 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Raw Markdown
              </button>
            </div>

            {/* Action Buttons */}
            <button
              onClick={handleCopy}
              className="px-2.5 py-1.5 rounded-lg text-xs font-medium border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 flex items-center gap-1 cursor-pointer transition-colors"
              title="Copy markdown content"
            >
              <span>{copied ? '✅' : '📋'}</span>
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>

            <button
              onClick={handleDownload}
              className="px-2.5 py-1.5 rounded-lg text-xs font-medium border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 flex items-center gap-1 cursor-pointer transition-colors"
              title="Download report file"
            >
              <span>⬇️</span>
              <span>Download</span>
            </button>

            <button
              onClick={onClose}
              className="ml-2 w-8 h-8 rounded-lg flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 transition-colors cursor-pointer text-base"
              title="Close modal"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Report Content Body */}
        <div className="flex-1 overflow-y-auto p-6 text-sm bg-white">
          {activeTab === 'rendered' ? (
            <div className="max-w-3xl mx-auto space-y-1">{renderMarkdownContent(markdown)}</div>
          ) : (
            <div className="bg-slate-900 text-slate-100 p-4 rounded-xl font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed shadow-inner">
              {markdown || '# No report available'}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-100 bg-slate-50/70 flex items-center justify-between text-xs text-slate-500">
          <span>Generated by VulnFlow Autonomous Engine</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 text-white hover:bg-slate-800 cursor-pointer shadow-xs"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
