"use client";

import { useState } from "react";
import Navbar from "@/components/Navbar";
import ProtectedRoute from "@/components/ProtectedRoute";
import StatusBadge from "@/components/StatusBadge";
import { apiClient, extractErrorMessage, uploadFormData } from "@/lib/api";
import { Camera, FileCheck, ScanFace, ShieldAlert } from "lucide-react";

type Step = "document" | "face" | "liveness" | "fraud" | "done";

interface DocResult {
  document_upload_id: string;
  tamper_risk_score: number;
  ocr_extracted_fields: Record<string, string>;
  tamper_indicators: Record<string, number>;
}

interface FaceResult {
  face_match_id: string;
  similarity_score: number;
  match_passed: boolean;
}

interface LivenessResult {
  liveness_score: number;
  liveness_passed: boolean;
}

interface FraudResult {
  fraud_score_id: string;
  overall_score: number;
  status: string;
  signals: Record<string, unknown>;
}

function VerifyIdentityContent() {
  const [step, setStep] = useState<Step>("document");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [documentType, setDocumentType] = useState("national_id");
  const [documentFile, setDocumentFile] = useState<File | null>(null);
  const [docResult, setDocResult] = useState<DocResult | null>(null);

  const [selfieFile, setSelfieFile] = useState<File | null>(null);
  const [docPhotoFile, setDocPhotoFile] = useState<File | null>(null);
  const [faceResult, setFaceResult] = useState<FaceResult | null>(null);

  const [livenessFrames, setLivenessFrames] = useState<File[]>([]);
  const [livenessResult, setLivenessResult] = useState<LivenessResult | null>(null);

  const [fraudResult, setFraudResult] = useState<FraudResult | null>(null);

  async function runDocumentStep() {
    if (!documentFile) return;
    setLoading(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("file", documentFile);
      const { data } = await uploadFormData(`/ai/verify-document?document_type=${documentType}`, form);
      setDocResult(data);
      setStep("face");
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  async function runFaceStep() {
    if (!docResult || !selfieFile || !docPhotoFile) return;
    setLoading(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("selfie", selfieFile);
      form.append("document_photo", docPhotoFile);
      const { data } = await uploadFormData(
        `/ai/verify-face?document_upload_id=${docResult.document_upload_id}`,
        form
      );
      setFaceResult(data);
      setStep("liveness");
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  async function runLivenessStep() {
    if (!faceResult || livenessFrames.length < 2) return;
    setLoading(true);
    setError(null);
    try {
      const form = new FormData();
      livenessFrames.forEach((f) => form.append("frames", f));
      const { data } = await uploadFormData(
        `/ai/liveness-check?face_match_id=${faceResult.face_match_id}`,
        form
      );
      setLivenessResult(data);
      setStep("fraud");
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  async function runFraudStep() {
    if (!docResult || !faceResult) return;
    setLoading(true);
    setError(null);
    try {
      const { data } = await apiClient.post("/ai/fraud-score", {
        document_upload_id: docResult.document_upload_id,
        face_match_id: faceResult.face_match_id,
      });
      setFraudResult(data);
      setStep("done");
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  const steps: { id: Step; label: string; icon: typeof FileCheck }[] = [
    { id: "document", label: "Document", icon: FileCheck },
    { id: "face", label: "Face match", icon: ScanFace },
    { id: "liveness", label: "Liveness", icon: Camera },
    { id: "fraud", label: "Fraud score", icon: ShieldAlert },
  ];

  return (
    <main>
      <Navbar />
      <div className="max-w-2xl mx-auto px-6 py-10">
        <h1 className="text-2xl font-semibold text-gray-900 mb-2">Identity Verification</h1>
        <p className="text-gray-500 mb-8 text-sm">
          Upload your ID and selfie for real OCR, tamper detection, face matching, and liveness analysis.
          Results feed into issuer credential approval workflows.
        </p>

        <div className="flex gap-2 mb-8 flex-wrap">
          {steps.map((s) => (
            <div
              key={s.id}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium ${
                step === s.id || steps.findIndex((x) => x.id === step) > steps.findIndex((x) => x.id === s.id)
                  ? "bg-brand-600 text-white"
                  : "bg-gray-100 text-gray-400"
              }`}
            >
              <s.icon className="w-3.5 h-3.5" />
              {s.label}
            </div>
          ))}
        </div>

        {error && <div className="bg-red-50 text-red-700 text-sm rounded-lg px-3 py-2 mb-6">{error}</div>}

        {step === "document" && (
          <div className="card space-y-4">
            <label className="block text-sm font-medium text-gray-700">Document type</label>
            <select className="input-field" value={documentType} onChange={(e) => setDocumentType(e.target.value)}>
              <option value="national_id">National ID</option>
              <option value="passport">Passport</option>
              <option value="student_id">Student ID</option>
              <option value="drivers_license">Driver&apos;s License</option>
            </select>
            <label className="block text-sm font-medium text-gray-700">Document image (JPEG/PNG)</label>
            <input
              type="file"
              accept="image/jpeg,image/png,image/webp"
              className="text-sm"
              onChange={(e) => setDocumentFile(e.target.files?.[0] || null)}
            />
            <button
              onClick={runDocumentStep}
              disabled={!documentFile || loading}
              className="btn-primary w-full"
            >
              {loading ? "Analyzing document..." : "Verify document"}
            </button>
          </div>
        )}

        {step === "face" && docResult && (
          <div className="card space-y-4">
            <div className="bg-gray-50 rounded-lg p-3 text-sm">
              <p className="text-gray-500 mb-1">Document tamper risk: {(docResult.tamper_risk_score * 100).toFixed(1)}%</p>
              <p className="text-xs text-gray-400 font-mono">{JSON.stringify(docResult.ocr_extracted_fields)}</p>
            </div>
            <label className="block text-sm font-medium text-gray-700">Selfie (live capture)</label>
            <input type="file" accept="image/*" capture="user" className="text-sm" onChange={(e) => setSelfieFile(e.target.files?.[0] || null)} />
            <label className="block text-sm font-medium text-gray-700">Photo from document</label>
            <input type="file" accept="image/*" className="text-sm" onChange={(e) => setDocPhotoFile(e.target.files?.[0] || null)} />
            <button onClick={runFaceStep} disabled={!selfieFile || !docPhotoFile || loading} className="btn-primary w-full">
              {loading ? "Matching faces..." : "Run face match"}
            </button>
          </div>
        )}

        {step === "liveness" && faceResult && (
          <div className="card space-y-4">
            <div className="bg-gray-50 rounded-lg p-3 text-sm">
              Similarity: {(faceResult.similarity_score * 100).toFixed(1)}% —{" "}
              {faceResult.match_passed ? "Match passed" : "Match failed"}
            </div>
            <label className="block text-sm font-medium text-gray-700">Liveness frames (2–10 photos, slight head movement)</label>
            <input
              type="file"
              accept="image/*"
              capture="user"
              multiple
              className="text-sm"
              onChange={(e) => setLivenessFrames(Array.from(e.target.files || []))}
            />
            <p className="text-xs text-gray-400">{livenessFrames.length} frame(s) selected</p>
            <button
              onClick={runLivenessStep}
              disabled={livenessFrames.length < 2 || loading}
              className="btn-primary w-full"
            >
              {loading ? "Checking liveness..." : "Run liveness check"}
            </button>
          </div>
        )}

        {step === "fraud" && livenessResult && (
          <div className="card space-y-4">
            <div className="bg-gray-50 rounded-lg p-3 text-sm">
              Liveness score: {(livenessResult.liveness_score * 100).toFixed(1)}% —{" "}
              {livenessResult.liveness_passed ? "Passed" : "Failed"}
            </div>
            <button onClick={runFraudStep} disabled={loading} className="btn-primary w-full">
              {loading ? "Computing fraud score..." : "Compute final fraud assessment"}
            </button>
          </div>
        )}

        {step === "done" && fraudResult && (
          <div className="card space-y-4">
            <div className="flex items-center gap-3">
              <StatusBadge status={fraudResult.status.toLowerCase()} />
              <span className="text-sm text-gray-600">
                Overall risk: {(fraudResult.overall_score * 100).toFixed(1)}%
              </span>
            </div>
            <pre className="bg-gray-50 rounded-lg p-3 text-xs overflow-auto">{JSON.stringify(fraudResult.signals, null, 2)}</pre>
            <p className="text-sm text-gray-500">
              Assessment ID: <span className="font-mono">{fraudResult.fraud_score_id}</span>
            </p>
          </div>
        )}
      </div>
    </main>
  );
}

export default function VerifyIdentityPage() {
  return (
    <ProtectedRoute allowedRoles={["user"]}>
      <VerifyIdentityContent />
    </ProtectedRoute>
  );
}
