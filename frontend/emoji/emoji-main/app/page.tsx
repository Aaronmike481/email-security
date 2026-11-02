"use client";
import { useState } from "react";

export default function EmailAuditor() {
  const [domain, setDomain] = useState("");
  const [emails, setEmails] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, emails }),
      });
      const data = await res.json();
      setResult(data);
    } catch (error) {
      alert("Failed to connect to Go server");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-gray-950 text-white p-8 font-sans">
      <div className="max-w-4xl mx-auto space-y-8">
        
      
        <div className="border-b border-gray-800 pb-4">
          <h1 className="text-3xl font-bold">Email Security Audit</h1>
          <p className="text-gray-400 mt-2">Detect DMARC misconfigurations, lookalike domains, and data breaches.</p>
        </div>

        
        <div className="bg-gray-900 p-6 rounded-lg border border-gray-800 space-y-4">
          <div>
            <label className="block text-sm font-bold text-gray-400 mb-2">Target Domain</label>
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="e.g., clientcompany.com"
              className="w-full p-3 bg-black border border-gray-700 rounded-lg focus:border-blue-500 outline-none"
            />
          </div>
          <div>
            <label className="block text-sm font-bold text-gray-400 mb-2">Employee Emails (Optional, comma separated)</label>
            <input
              value={emails}
              onChange={(e) => setEmails(e.target.value)}
              placeholder="ceo@client.com, hr@client.com"
              className="w-full p-3 bg-black border border-gray-700 rounded-lg focus:border-blue-500 outline-none"
            />
          </div>
          <button 
            onClick={handleScan} 
            disabled={loading || !domain} 
            className="w-full bg-blue-600 px-6 py-3 rounded-lg font-bold hover:bg-blue-500 disabled:bg-gray-700 transition-colors"
          >
            {loading ? "Scanning..." : "Run Security Scan"}
          </button>
        </div>

        
        {result && (
          <div className="space-y-6">
            {result.error ? (
               <div className="bg-red-900/20 border border-red-500 p-4 rounded-lg text-red-400">
                 <strong>Error:</strong> {result.error}
               </div>
            ) : (
              <>
                
                <div className="bg-gray-900 p-6 rounded-lg border border-gray-800">
                  <div className="flex justify-between items-center mb-4">
                    <h2 className="text-xl font-bold">Security Verdict</h2>
                    <span className={`px-3 py-1 rounded text-sm font-bold ${
                      result.judge_verdict?.severity === "CRITICAL" ? "bg-red-500/20 text-red-500" :
                      result.judge_verdict?.severity === "HIGH" ? "bg-orange-500/20 text-orange-500" :
                      "bg-green-500/20 text-green-500"
                    }`}>
                      {result.judge_verdict?.severity || "UNKNOWN"}
                    </span>
                  </div>
                  <p className="text-gray-300 leading-relaxed">
                    {result.judge_verdict?.executive_summary || "No summary generated."}
                  </p>
                </div>

                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  
                  {/* Technical Fixes */}
                  <div className="bg-gray-900 p-6 rounded-lg border border-gray-800">
                    <h2 className="text-lg font-bold text-blue-400 mb-4">🛠️ Technical Fixes (We Provide)</h2>
                    {result.auto_remediation?.length > 0 ? (
                      <ul className="list-disc list-inside text-gray-300 space-y-2">
                        {result.auto_remediation.map((fix: string, i: number) => (
                          <li key={i}>{fix}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-gray-500">No immediate technical fixes required.</p>
                    )}
                  </div>

                
                  <div className="bg-gray-900 p-6 rounded-lg border border-gray-800">
                    <h2 className="text-lg font-bold text-orange-400 mb-4"> Company Actions Required</h2>
                    {result.company_action?.length > 0 ? (
                      <ul className="list-disc list-inside text-gray-300 space-y-2">
                        {result.company_action.map((action: string, i: number) => (
                          <li key={i}>{action}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-gray-500">No internal company actions required.</p>
                    )}
                  </div>
                </div>

               
                <div className="bg-gray-900 p-6 rounded-lg border border-gray-800">
                  <div className="flex justify-between items-center mb-4">
                    <h2 className="text-lg font-bold">Raw Findings</h2>
                    
{result.pdf_report && (
  <a 
    href={`data:application/pdf;base64,${result.pdf_report}`} 
    download={`${result.domain}_report.pdf`}
    className="bg-green-600 hover:bg-green-500 px-4 py-2 rounded font-bold text-sm transition-colors"
  >
    📥 Download Full PDF Report
  </a>
)}
                  </div>
                  
                  <div className="grid grid-cols-3 gap-4 mb-4 text-sm">
                    <div className="bg-black p-3 rounded border border-gray-800">
                      <span className="text-gray-500 block mb-1">Provider</span>
                      <span className="font-bold">{result.provider || "Unknown"}</span>
                    </div>
                    <div className="bg-black p-3 rounded border border-gray-800">
                      <span className="text-gray-500 block mb-1">Lookalikes</span>
                      <span className="font-bold text-red-400">{result.lookalikes?.length || 0}</span>
                    </div>
                    <div className="bg-black p-3 rounded border border-gray-800">
                      <span className="text-gray-500 block mb-1">Breaches</span>
                      <span className="font-bold text-red-400">{result.breaches?.length || 0}</span>
                    </div>
                  </div>

                  <pre className="bg-black p-4 rounded text-xs overflow-auto max-h-60 border border-gray-800 text-gray-400 font-mono">
                    {JSON.stringify(result.dmarc_data, null, 2)}
                  </pre>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </main>
  );
}