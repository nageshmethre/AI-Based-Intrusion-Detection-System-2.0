import React, { useState, useEffect } from 'react';
import { 
  X, 
  Cpu, 
  Activity, 
  CheckCircle, 
  AlertTriangle, 
  TrendingUp, 
  TrendingDown,
  Info,
  Layers
} from 'lucide-react';
import { fetchAlertExplanation } from '../services/api';

export default function AiExplainerModal({ alertId, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!alertId) return;
    setLoading(true);
    fetchAlertExplanation(alertId)
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [alertId]);

  if (!alertId) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-blue-600/20 text-blue-400 rounded-lg border border-blue-500/30">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Explainable AI (XAI) & Feature Attribution Analysis
              </h3>
              <p className="text-xs text-slate-400">
                Random Forest Decision Tree Forensics for Alert #{alertId}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300">
          {loading ? (
            <div className="py-12 text-center text-slate-400 flex items-center justify-center space-x-2">
              <Activity className="w-5 h-5 animate-spin text-cyan-400" />
              <span>Attributing decision tree feature importances...</span>
            </div>
          ) : data ? (
            <>
              {/* Alert Classification Pill */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <span className="text-[10px] font-mono uppercase text-slate-500 block">Classified Attack Vector</span>
                  <span className="text-base font-bold text-white font-mono">{data.prediction}</span>
                </div>
                <div>
                  <span className="text-[10px] font-mono uppercase text-slate-500 block">Ensemble Confidence</span>
                  <span className="text-base font-bold text-cyan-400 font-mono">{data.confidence_percentage}</span>
                </div>
                <div>
                  <span className="text-[10px] font-mono uppercase text-slate-500 block">Target Flow</span>
                  <span className="text-xs font-mono text-slate-300">{data.src_ip} &rarr; {data.dst_ip}:{data.dst_port}</span>
                </div>
              </div>

              {/* Top Contributing Features */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center">
                  <Layers className="w-4 h-4 text-cyan-400 mr-1.5" />
                  Dominant Anomalous Flow Features Driving The Prediction
                </h4>
                <div className="space-y-2">
                  {(data.top_contributing_features || []).map((feat) => (
                    <div key={feat.feature} className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-cyan-300 text-xs">{feat.feature}</span>
                        <div className="flex items-center space-x-1.5 text-[11px]">
                          {feat.direction === 'ABNORMALLY_HIGH' ? (
                            <span className="text-red-400 flex items-center font-bold">
                              <TrendingUp className="w-3.5 h-3.5 mr-0.5" />
                              +{feat.deviation_percent}% above baseline
                            </span>
                          ) : (
                            <span className="text-blue-400 flex items-center font-bold">
                              <TrendingDown className="w-3.5 h-3.5 mr-0.5" />
                              {feat.deviation_percent}% below baseline
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center justify-between text-[10px] text-slate-400 mt-1">
                        <span>Flow Value: <strong className="text-white">{feat.value}</strong></span>
                        <span>Normal Benign Mean: <strong className="text-slate-300">{feat.normal_baseline}</strong></span>
                        <span>Anomaly Weight: <strong className="text-amber-400">{feat.importance_score}/10</strong></span>
                      </div>
                    </div>
                  ))}
                  {(data.top_contributing_features || []).length === 0 && (
                    <div className="text-slate-500 text-center py-4">
                      Rule-based signature trigger or standard baseline values.
                    </div>
                  )}
                </div>
              </div>

              {/* Forensic Narrative Reasoning */}
              <div className="p-4 bg-blue-950/20 border border-blue-500/30 rounded-xl space-y-2">
                <span className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center">
                  <Info className="w-4 h-4 mr-1.5" />
                  Automated Forensic Narrative Reasoning
                </span>
                <ul className="list-disc pl-5 space-y-1 text-slate-300 text-xs leading-relaxed">
                  {(data.forensic_reasoning || []).map((point, idx) => (
                    <li key={idx}>{point}</li>
                  ))}
                </ul>
              </div>
            </>
          ) : (
            <div className="text-center py-8 text-slate-500">Could not retrieve explanation.</div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold transition"
          >
            Close Explanation
          </button>
        </div>
      </div>
    </div>
  );
}
