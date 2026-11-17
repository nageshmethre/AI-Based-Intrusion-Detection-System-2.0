import React, { useState, useRef, useEffect } from 'react';
import { HelpCircle, X, ExternalLink, Info } from 'lucide-react';

export default function ContextHelp({ title, description, formula, example, onNavigate }) {
  const [isOpen, setIsOpen] = useState(false);
  const popoverRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (popoverRef.current && !popoverRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  return (
    <div className="relative inline-flex items-center ml-1.5 align-middle" ref={popoverRef}>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setIsOpen(!isOpen);
        }}
        className="text-slate-400 hover:text-cyan-400 transition-colors focus:outline-none p-0.5 rounded-full hover:bg-slate-800"
        title={`Learn more about ${title}`}
      >
        <HelpCircle className="w-3.5 h-3.5" />
      </button>

      {isOpen && (
        <div className="absolute left-1/2 -translate-x-1/2 bottom-full mb-2 z-50 w-72 sm:w-80 p-4 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl backdrop-blur-md text-left text-xs animate-in fade-in duration-200">
          <div className="flex items-start justify-between border-b border-slate-800 pb-2 mb-2.5">
            <div className="flex items-center space-x-1.5 text-cyan-400 font-bold uppercase tracking-wider text-[11px]">
              <Info className="w-3.5 h-3.5" />
              <span>{title}</span>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="text-slate-500 hover:text-slate-200 text-xs p-0.5"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="text-slate-300 leading-relaxed space-y-2">
            <p>{description}</p>

            {formula && (
              <div className="p-2 bg-slate-950/80 rounded border border-slate-800 font-mono text-[11px] text-cyan-300">
                <span className="text-slate-500 font-sans block text-[10px] uppercase">Formula / Logic:</span>
                {formula}
              </div>
            )}

            {example && (
              <div className="text-slate-400 text-[11px] italic">
                <span className="text-slate-300 font-semibold not-italic">SOC Context: </span>
                {example}
              </div>
            )}
          </div>

          {onNavigate && (
            <button
              type="button"
              onClick={() => {
                setIsOpen(false);
                onNavigate();
              }}
              className="mt-3 w-full py-1.5 px-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 rounded text-[11px] font-semibold flex items-center justify-center space-x-1 transition-colors"
            >
              <span>View Full Guide Section</span>
              <ExternalLink className="w-3 h-3 ml-1" />
            </button>
          )}
        </div>
      )}
    </div>
  );
}
