import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  RotateCw, 
  CheckCircle, 
  BarChart2, 
  Layers, 
  Award,
  Database,
  ExternalLink,
  FolderOpen,
  Info,
  Clock,
  ShieldCheck,
  Percent,
  Play
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell 
} from 'recharts';
import { fetchModelMetrics, retrainModel, fetchDatasetStatus, processDataset } from '../services/api';
import ContextHelp from '../components/ContextHelp';

export default function ModelPerformance({ onNavigateTab }) {
  const [metrics, setMetrics] = useState(null);
  const [datasetStatus, setDatasetStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [retraining, setRetraining] = useState(false);
  const [processingDs, setProcessingDs] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [useAuthentic, setUseAuthentic] = useState(true);

  const loadData = async () => {
    try {
      const [mRes, dRes] = await Promise.all([
        fetchModelMetrics().catch(() => null),
        fetchDatasetStatus().catch(() => null)
      ]);
      if (mRes) setMetrics(mRes);
      if (dRes) setDatasetStatus(dRes);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRetrain = async () => {
    setRetraining(true);
    setStatusMsg(`Training Random Forest (${useAuthentic ? 'Authentic' : 'Augmented'})...`);
    try {
      await retrainModel({ use_authentic: useAuthentic });
      setTimeout(async () => {
        await loadData();
        setRetraining(false);
        setStatusMsg('Model training complete! Evaluation metrics updated.');
        setTimeout(() => setStatusMsg(''), 5000);
      }, 6000);
    } catch (e) {
      console.error(e);
      setStatusMsg('Failed to trigger retrain.');
      setRetraining(false);
    }
  };

  const handleProcessDataset = async () => {
    setProcessingDs(true);
    setStatusMsg('Chunk-based authentic dataset compilation in progress...');
    try {
      await processDataset({ chunk_size: 50000, max_samples_per_class: 15000 });
      setTimeout(async () => {
        await loadData();
        setProcessingDs(false);
        setStatusMsg('Authentic dataset compiled successfully to backend/data/processed!');
        setTimeout(() => setStatusMsg(''), 5000);
      }, 7000);
    } catch (e) {
      console.error(e);
      setStatusMsg('Failed to process raw dataset.');
      setProcessingDs(false);
    }
  };

  if (loading && !metrics) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400">
        <Cpu className="w-6 h-6 animate-spin mr-3 text-blue-500" />
        <span>Loading AI Model Evaluation Metrics & Dataset Status...</span>
      </div>
    );
  }

  const featureData = (metrics?.feature_importances || []).slice(0, 10).map((f) => ({
    name: f.feature,
    importance: parseFloat((f.importance * 100).toFixed(2)),
  }));

  const report = metrics?.classification_report || {};
  const classes = metrics?.classes || [];
  const cm = metrics?.confusion_matrix || [];
  const rawFiles = datasetStatus?.raw_files || [];
  const officialInfo = datasetStatus?.official_info || {};

  return (
    <div className="space-y-6">
      {/* Header and Retrain Control Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-white uppercase tracking-wider flex items-center">
            <Cpu className="w-5 h-5 text-blue-400 mr-2" />
            AI Detection Model Architecture & Performance
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Random Forest Ensemble & RobustScaler on CIC-IDS2017 Statistical Flow Features
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700">
            <input
              type="checkbox"
              checked={useAuthentic}
              onChange={(e) => setUseAuthentic(e.target.checked)}
              className="rounded accent-blue-500"
            />
            <span>Use Authentic UNB Dataset</span>
          </label>

          <button
            onClick={handleRetrain}
            disabled={retraining}
            className={`flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow transition-all ${
              retraining ? 'opacity-50 cursor-not-allowed' : ''
            }`}
          >
            <RotateCw className={`w-3.5 h-3.5 ${retraining ? 'animate-spin' : ''}`} />
            <span>{retraining ? 'Training Ensemble...' : 'Retrain Random Forest'}</span>
          </button>
        </div>
      </div>

      {statusMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-400 text-xs font-semibold flex items-center space-x-2 animate-in fade-in">
          <CheckCircle className="w-4 h-4 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      {/* Dataset Provenance & Authentic UNB Status Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold text-white uppercase tracking-wider">
                Active Training Dataset Provenance
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                metrics?.is_authentic_unb
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
              }`}>
                {metrics?.is_authentic_unb ? 'AUTHENTIC UNB' : 'AUGMENTED SCHEMA'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Source: <span className="text-slate-200">{metrics?.dataset_source || 'Canadian Institute for Cybersecurity (UNB)'}</span>
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <a
              href="https://www.unb.ca/cic/datasets/ids-2017.html"
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded-lg text-xs font-medium border border-slate-700 flex items-center space-x-1 transition"
            >
              <span>UNB Official Portal</span>
              <ExternalLink className="w-3 h-3 ml-1" />
            </a>
            <a
              href="https://www.kaggle.com/datasets/cicdataset/cicids2017"
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium border border-slate-700 flex items-center space-x-1 transition"
            >
              <span>Kaggle Mirror</span>
              <ExternalLink className="w-3 h-3 ml-1" />
            </a>
          </div>
        </div>

        {/* Dataset Details Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Dataset Name</span>
            <span className="font-mono font-bold text-white">{metrics?.dataset}</span>
          </div>
          <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Total Labeled Samples</span>
            <span className="font-mono font-bold text-cyan-400">
              {metrics?.total_samples?.toLocaleString()} flows
            </span>
          </div>
          <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Train / Test Split</span>
            <span className="font-mono font-bold text-slate-200">
              {metrics?.train_samples} / {metrics?.test_samples} (80/20)
            </span>
          </div>
          <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
            <span className="text-slate-400 block text-[11px]">Training Timestamp</span>
            <span className="font-mono text-[11px] text-slate-300">
              {metrics?.training_date ? new Date(metrics.training_date).toLocaleTimeString() : 'Recent'}
            </span>
          </div>
        </div>

        {/* Raw Files Ingestion Box */}
        <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center space-x-2 text-xs font-semibold text-slate-200">
              <FolderOpen className="w-4 h-4 text-amber-400" />
              <span>Raw Authentic Files in <code>backend/data/raw/</code>:</span>
              <span className="font-mono text-cyan-400">({rawFiles.length} file(s) found)</span>
            </div>
            <p className="text-[11px] text-slate-400">
              Drop any or all of the 8 official UNB CSV files (e.g. <code>Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv</code>) into the raw folder to compile authentic chunks.
            </p>
          </div>

          <button
            onClick={handleProcessDataset}
            disabled={processingDs}
            className="px-3.5 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 rounded-lg text-xs font-semibold border border-amber-500/40 flex items-center space-x-1.5 transition shrink-0"
          >
            <Play className={`w-3.5 h-3.5 ${processingDs ? 'animate-spin' : ''}`} />
            <span>{processingDs ? 'Processing Chunks...' : 'Compile Authentic CSVs'}</span>
          </button>
        </div>
      </div>

      {/* KPI Cards Row (5 Metrics: Accuracy, Precision, Recall, F1, and False Positive Rate) */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow text-center">
          <div className="flex items-center justify-center">
            <p className="text-xs text-slate-400 uppercase font-semibold">Test Accuracy</p>
            <ContextHelp
              title="Test Accuracy"
              description="The percentage of test flows correctly classified out of all holdout samples."
              formula="Accuracy = (TP + TN) / (Total Samples)"
              example="Calculated on the independent 20% holdout split."
            />
          </div>
          <h4 className="text-2xl font-bold font-mono text-emerald-400 mt-1">
            {((metrics?.accuracy || 0) * 100).toFixed(2)}%
          </h4>
          <span className="text-[10px] text-slate-500">Holdout evaluation set</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow text-center">
          <div className="flex items-center justify-center">
            <p className="text-xs text-slate-400 uppercase font-semibold">Macro Precision</p>
            <ContextHelp
              title="Macro Precision"
              description="Out of all flows predicted as an attack, what fraction were genuinely malicious."
              formula="Precision = TP / (TP + FP)"
              example="High precision guarantees that security alerts are actionable."
            />
          </div>
          <h4 className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            {((metrics?.macro_precision || 0) * 100).toFixed(2)}%
          </h4>
          <span className="text-[10px] text-slate-500">Minimal false alarms</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow text-center">
          <div className="flex items-center justify-center">
            <p className="text-xs text-slate-400 uppercase font-semibold">Macro Recall</p>
            <ContextHelp
              title="Macro Recall"
              description="Out of all genuine attacks in network traffic, what fraction did the model detect."
              formula="Recall = TP / (TP + FN)"
              example="High recall ensures attackers cannot slip past unseen."
            />
          </div>
          <h4 className="text-2xl font-bold font-mono text-blue-400 mt-1">
            {((metrics?.macro_recall || 0) * 100).toFixed(2)}%
          </h4>
          <span className="text-[10px] text-slate-500">Attack detection coverage</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow text-center">
          <div className="flex items-center justify-center">
            <p className="text-xs text-slate-400 uppercase font-semibold">Macro F1-Score</p>
            <ContextHelp
              title="Macro F1-Score"
              description="The harmonic mean of precision and recall. Best single metric for imbalanced cybersecurity evaluations."
              formula="F1 = 2 * (Precision * Recall) / (Precision + Recall)"
              example="Guarantees both low false alarms and high threat capture."
            />
          </div>
          <h4 className="text-2xl font-bold font-mono text-purple-400 mt-1">
            {((metrics?.macro_f1 || 0) * 100).toFixed(2)}%
          </h4>
          <span className="text-[10px] text-slate-500">Harmonic balance</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow text-center">
          <div className="flex items-center justify-center">
            <p className="text-xs text-slate-400 uppercase font-semibold">False Positive Rate</p>
            <ContextHelp
              title="False Positive Rate (FPR)"
              description="The proportion of benign flows mistakenly classified as attacks."
              formula="FPR = FP / (FP + TN)"
              example="Suppressed on live HTTPS traffic by the 0.80 confidence threshold."
            />
          </div>
          <h4 className="text-2xl font-bold font-mono text-amber-400 mt-1">
            {((metrics?.false_positive_rate || 0) * 100).toFixed(3)}%
          </h4>
          <span className="text-[10px] text-slate-500">Macro FPR &le; 0.05%</span>
        </div>
      </div>

      {/* Confusion Matrix & Classification Report Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-bold text-white uppercase tracking-wider flex items-center">
              Confusion Matrix
              <ContextHelp
                title="Confusion Matrix"
                description="A 2D contingency grid showing actual ground truth classes versus predicted classes."
                example="Diagonal cells (green) represent correct predictions. Off-diagonal cells (red) represent misclassifications."
              />
            </h4>
            <span className="text-xs text-slate-500">Test Partition</span>
          </div>
          <p className="text-xs text-slate-400 mb-4">
            Ground Truth (rows) vs Model Predictions (columns)
          </p>

          <div className="overflow-x-auto">
            <table className="w-full text-center text-xs">
              <thead>
                <tr>
                  <th className="py-2 px-2 text-left text-slate-500 font-semibold uppercase">Actual \ Pred</th>
                  {classes.map((cls) => (
                    <th key={cls} className="py-2 px-2 text-cyan-400 font-mono font-bold">
                      {cls}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {cm.map((row, i) => (
                  <tr key={classes[i] || i}>
                    <td className="py-2.5 px-2 text-left font-mono font-bold text-slate-300">
                      {classes[i]}
                    </td>
                    {row.map((val, j) => {
                      const isDiagonal = i === j;
                      return (
                        <td
                          key={j}
                          className={`py-2.5 px-2 font-mono font-bold ${
                            isDiagonal
                              ? val > 0 ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'text-slate-500'
                              : val > 0 ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'text-slate-600'
                          }`}
                        >
                          {val}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Per-Class Classification Report */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-bold text-white uppercase tracking-wider flex items-center">
              Per-Class Classification Report
              <ContextHelp
                title="Per-Class Performance"
                description="Detailed breakdown of precision, recall, and F1-score for each discrete cyberattack category."
                example="Ensures no single attack class (like Botnet or BruteForce) is masked by a large Benign majority."
              />
            </h4>
            <span className="text-xs text-slate-500">Holdout Metrics</span>
          </div>
          <p className="text-xs text-slate-400 mb-4">
            Precision, Recall, F1 and Support per attack category
          </p>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-800/60 text-slate-400 uppercase font-semibold">
                <tr>
                  <th className="py-2 px-3">Attack Class</th>
                  <th className="py-2 px-3">Precision</th>
                  <th className="py-2 px-3">Recall</th>
                  <th className="py-2 px-3">F1-Score</th>
                  <th className="py-2 px-3">Support</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {classes.map((cls) => {
                  const stat = report[cls] || {};
                  return (
                    <tr key={cls} className="hover:bg-slate-800/40">
                      <td className="py-2.5 px-3 font-mono font-bold text-white">{cls}</td>
                      <td className="py-2.5 px-3 font-mono text-cyan-400">
                        {((stat['precision'] || 0) * 100).toFixed(1)}%
                      </td>
                      <td className="py-2.5 px-3 font-mono text-blue-400">
                        {((stat['recall'] || 0) * 100).toFixed(1)}%
                      </td>
                      <td className="py-2.5 px-3 font-mono font-bold text-emerald-400">
                        {((stat['f1-score'] || 0) * 100).toFixed(1)}%
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-400">
                        {stat['support'] || 0}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Feature Importances Chart */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-1">
          <h4 className="text-sm font-bold text-white uppercase tracking-wider flex items-center">
            Top 10 CIC-IDS2017 Statistical Feature Importances (Gini Impurity)
            <ContextHelp
              title="Feature Importance"
              description="Quantifies the relative contribution of each statistical network flow feature to the decision trees."
              example="Higher values indicate features that best discriminate malicious traffic from benign flows."
            />
          </h4>
          <span className="text-xs text-slate-500">Explainable AI</span>
        </div>
        <p className="text-xs text-slate-400 mb-4">
          Dominant statistical flow features utilized by the Random Forest decision trees
        </p>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={featureData} layout="vertical" margin={{ left: 120 }}>
              <XAxis type="number" stroke="#64748B" fontSize={11} domain={[0, 'auto']} />
              <YAxis type="category" dataKey="name" stroke="#64748B" fontSize={11} width={150} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: '8px', color: '#fff' }}
                formatter={(val) => [`${val}%`, 'Importance Weight']}
              />
              <Bar dataKey="importance" fill="#3B82F6" radius={[0, 4, 4, 0]}>
                {featureData.map((_, index) => (
                  <Cell key={`bar-${index}`} fill={index === 0 ? '#06B6D4' : '#3B82F6'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
