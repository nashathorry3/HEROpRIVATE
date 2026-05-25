/**
 * Census Platform — Main Census Form Page
 * Multi-step wizard: Identity → Face → Demographics
 * Offline-first: works without internet, syncs when connected
 * RTL-aware: supports Arabic, Kurdish, Turkmen, English
 */
"use client";

import { useState, useCallback, useEffect } from "react";
import { useRouter } from "next/navigation";

// ─── Types ──────────────────────────────────────────────────────────────────

type VerificationStep = "otp" | "face" | "census" | "complete";

interface OTPState {
  phoneNumber: string;
  channel: "sms" | "whatsapp" | "voice";
  sent: boolean;
  verified: boolean;
  sessionToken?: string;
  error?: string;
}

interface FaceState {
  verified: boolean;
  zkpTokenId?: string;
  proof?: string;
  nullifier?: string;
  error?: string;
}

interface DemographicData {
  regionCode: string;
  districtCode?: string;
  isUrban?: boolean;
  ethnicityCode?: string;
  languageCode?: string;
  religionCode?: string;
  ageBracket?: string;
  genderCode?: string;
  householdSize?: number;
  educationLevel?: string;
  employmentStatus?: string;
  housingType?: string;
}

// ─── Reference Data ─────────────────────────────────────────────────────────

const AGE_BRACKETS = [
  { code: "under-18", label_ar: "أقل من 18", label_en: "Under 18" },
  { code: "18-24", label_ar: "18-24", label_en: "18–24" },
  { code: "25-34", label_ar: "25-34", label_en: "25–34" },
  { code: "35-44", label_ar: "35-44", label_en: "35–44" },
  { code: "45-54", label_ar: "45-54", label_en: "45–54" },
  { code: "55-64", label_ar: "55-64", label_en: "55–64" },
  { code: "65+", label_ar: "65 فأكبر", label_en: "65 and over" },
];

const EDUCATION_LEVELS = [
  { code: "none", label_ar: "بدون تعليم", label_en: "No formal education" },
  { code: "primary", label_ar: "ابتدائي", label_en: "Primary" },
  { code: "secondary", label_ar: "ثانوي", label_en: "Secondary" },
  { code: "vocational", label_ar: "مهني", label_en: "Vocational" },
  { code: "bachelor", label_ar: "بكالوريوس", label_en: "Bachelor's degree" },
  { code: "postgrad", label_ar: "دراسات عليا", label_en: "Postgraduate" },
];

// ─── Step 1: Phone OTP Verification ─────────────────────────────────────────

function OTPStep({
  state,
  onChange,
  onVerified,
  locale,
}: {
  state: OTPState;
  onChange: (s: OTPState) => void;
  onVerified: (token: string) => void;
  locale: string;
}) {
  const [otp, setOtp] = useState("");
  const [loading, setLoading] = useState(false);
  const isRTL = locale === "ar" || locale === "ku";

  const sendOTP = async () => {
    if (!state.phoneNumber || !/^\+\d{7,15}$/.test(state.phoneNumber)) {
      onChange({ ...state, error: locale === "ar" ? "رقم هاتف غير صحيح" : "Invalid phone number" });
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/v1/auth/otp/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          phone_number: state.phoneNumber,
          channel: state.channel,
          locale,
        }),
      });

      if (res.status === 429) {
        onChange({ ...state, error: locale === "ar" ? "طلبات كثيرة. انتظر 10 دقائق." : "Too many requests. Wait 10 minutes." });
        return;
      }

      if (!res.ok) throw new Error("Send failed");
      onChange({ ...state, sent: true, error: undefined });
    } catch {
      onChange({ ...state, error: locale === "ar" ? "فشل إرسال الرمز" : "Failed to send OTP" });
    } finally {
      setLoading(false);
    }
  };

  const verifyOTP = async () => {
    if (otp.length !== 6) return;
    setLoading(true);
    try {
      const res = await fetch("/v1/auth/otp/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone_number: state.phoneNumber, otp_code: otp }),
      });

      if (!res.ok) {
        const data = await res.json();
        onChange({ ...state, error: data.detail || "Verification failed" });
        return;
      }

      const data = await res.json();
      onChange({ ...state, verified: true, sessionToken: data.session_token, error: undefined });
      onVerified(data.session_token);
    } catch {
      onChange({ ...state, error: locale === "ar" ? "فشل التحقق" : "Verification failed" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6" dir={isRTL ? "rtl" : "ltr"}>
      <div>
        <h2 className="text-2xl font-bold text-gray-900">
          {locale === "ar" ? "التحقق من رقم الهاتف" : "Phone Verification"}
        </h2>
        <p className="mt-2 text-sm text-gray-600">
          {locale === "ar"
            ? "سنرسل رمز تحقق إلى هاتفك. لن يُحفظ رقم هاتفك في قاعدة البيانات."
            : "We'll send a verification code. Your phone number will not be stored."}
        </p>
      </div>

      {!state.sent ? (
        <>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              {locale === "ar" ? "رقم الهاتف (مع رمز الدولة)" : "Phone number (with country code)"}
            </label>
            <input
              type="tel"
              value={state.phoneNumber}
              onChange={(e) => onChange({ ...state, phoneNumber: e.target.value })}
              placeholder="+9647XXXXXXXXX"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg text-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              dir="ltr"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              {locale === "ar" ? "طريقة الاستلام" : "Delivery method"}
            </label>
            <div className="grid grid-cols-3 gap-3">
              {(["sms", "whatsapp", "voice"] as const).map((ch) => (
                <button
                  key={ch}
                  onClick={() => onChange({ ...state, channel: ch })}
                  className={`px-4 py-3 rounded-lg border-2 text-sm font-medium transition-colors ${
                    state.channel === ch
                      ? "border-blue-500 bg-blue-50 text-blue-700"
                      : "border-gray-200 bg-white text-gray-600 hover:border-gray-300"
                  }`}
                >
                  {ch === "sms" ? "SMS" : ch === "whatsapp" ? "WhatsApp" : locale === "ar" ? "مكالمة" : "Voice Call"}
                </button>
              ))}
            </div>
          </div>

          <button
            onClick={sendOTP}
            disabled={loading || !state.phoneNumber}
            className="w-full py-4 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading
              ? (locale === "ar" ? "جاري الإرسال..." : "Sending...")
              : (locale === "ar" ? "إرسال رمز التحقق" : "Send Verification Code")}
          </button>
        </>
      ) : (
        <>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              {locale === "ar" ? "أدخل الرمز المكون من 6 أرقام" : "Enter the 6-digit code"}
            </label>
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={6}
              value={otp}
              onChange={(e) => setOtp(e.target.value.replace(/\D/g, ""))}
              className="w-full px-4 py-4 border border-gray-300 rounded-lg text-3xl text-center tracking-widest font-mono focus:ring-2 focus:ring-blue-500"
              dir="ltr"
            />
            <p className="mt-2 text-xs text-gray-500">
              {locale === "ar" ? "صالح لمدة 5 دقائق" : "Valid for 5 minutes"}
            </p>
          </div>

          <button
            onClick={verifyOTP}
            disabled={loading || otp.length !== 6}
            className="w-full py-4 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 disabled:opacity-50 transition-colors"
          >
            {loading ? "..." : (locale === "ar" ? "تحقق" : "Verify")}
          </button>

          <button
            onClick={() => { onChange({ ...state, sent: false }); setOtp(""); }}
            className="w-full py-3 text-gray-600 text-sm hover:text-gray-900"
          >
            {locale === "ar" ? "إعادة الإرسال" : "Resend code"}
          </button>
        </>
      )}

      {state.error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          {state.error}
        </div>
      )}
    </div>
  );
}

// ─── Step 2: Face Verification ───────────────────────────────────────────────

function FaceVerificationStep({
  sessionToken,
  onVerified,
  locale,
}: {
  sessionToken: string;
  onVerified: (zkpData: { tokenId: string; proof: string; nullifier: string }) => void;
  locale: string;
}) {
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [capturing, setCapturing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();
  const isRTL = locale === "ar" || locale === "ku";

  const startCamera = async () => {
    try {
      const mediaStream = await navigator.mediaDevices.getUserMedia({
        video: { width: 640, height: 480, facingMode: "user" },
      });
      setStream(mediaStream);
    } catch {
      setError(locale === "ar" ? "لا يمكن الوصول إلى الكاميرا" : "Cannot access camera");
    }
  };

  const captureAndVerify = async () => {
    if (!stream) return;
    setLoading(true);

    try {
      const video = document.getElementById("camera-preview") as HTMLVideoElement;
      const canvas = document.createElement("canvas");
      canvas.width = 640;
      canvas.height = 480;
      canvas.getContext("2d")!.drawImage(video, 0, 0);

      const blob = await new Promise<Blob>((resolve) =>
        canvas.toBlob((b) => resolve(b!), "image/jpeg", 0.9)
      );
      const arrayBuffer = await blob.arrayBuffer();
      const base64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));

      // Stop camera stream immediately — don't keep it running
      stream.getTracks().forEach((t) => t.stop());
      setStream(null);

      const res = await fetch("/v1/auth/face/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image_base64: base64, session_token: sessionToken }),
      });

      if (!res.ok) {
        const data = await res.json();
        setError(data.detail || (locale === "ar" ? "فشل التحقق من الوجه" : "Face verification failed"));
        return;
      }

      const data = await res.json();
      onVerified({ tokenId: data.zkp_token_id, proof: data.proof, nullifier: data.nullifier });
    } catch {
      setError(locale === "ar" ? "حدث خطأ. حاول مجددًا." : "An error occurred. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6" dir={isRTL ? "rtl" : "ltr"}>
      <div>
        <h2 className="text-2xl font-bold text-gray-900">
          {locale === "ar" ? "التحقق من الهوية البيومترية" : "Biometric Verification"}
        </h2>
        <p className="mt-2 text-sm text-gray-600">
          {locale === "ar"
            ? "الصورة تُعالج فورًا ولا تُحفظ. نستخدم هذا لمنع التسجيل المكرر فقط."
            : "Your image is processed instantly and never stored. This prevents duplicate registrations only."}
        </p>
      </div>

      <div className="bg-gray-50 border-2 border-dashed border-gray-300 rounded-xl overflow-hidden" style={{ aspectRatio: "4/3" }}>
        {stream ? (
          <video
            id="camera-preview"
            autoPlay
            playsInline
            muted
            style={{ transform: "scaleX(-1)", width: "100%", height: "100%", objectFit: "cover" }}
            ref={(el) => { if (el) el.srcObject = stream; }}
          />
        ) : (
          <div className="flex items-center justify-center h-full">
            <div className="text-center text-gray-400">
              <div className="text-6xl mb-4">📷</div>
              <p>{locale === "ar" ? "اضغط لتشغيل الكاميرا" : "Press to start camera"}</p>
            </div>
          </div>
        )}
      </div>

      {!stream ? (
        <button
          onClick={startCamera}
          className="w-full py-4 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition-colors"
        >
          {locale === "ar" ? "تشغيل الكاميرا" : "Start Camera"}
        </button>
      ) : (
        <button
          onClick={captureAndVerify}
          disabled={loading}
          className="w-full py-4 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 disabled:opacity-50 transition-colors"
        >
          {loading ? (locale === "ar" ? "جاري التحقق..." : "Verifying...") : (locale === "ar" ? "التقاط والتحقق" : "Capture & Verify")}
        </button>
      )}

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          {error}
        </div>
      )}

      <div className="p-4 bg-blue-50 rounded-lg">
        <p className="text-xs text-blue-700">
          {locale === "ar"
            ? "🔒 خصوصيتك محمية: لا تُحفظ صورتك. نستخدم بصمة رياضية مشفرة فقط."
            : "🔒 Privacy protected: Your image is not stored. We use only a mathematical hash."}
        </p>
      </div>
    </div>
  );
}

// ─── Step 3: Demographic Census Form ─────────────────────────────────────────

function CensusFormStep({
  zkpData,
  onSubmitted,
  locale,
  referenceData,
}: {
  zkpData: { proof: string; nullifier: string };
  onSubmitted: (code: string) => void;
  locale: string;
  referenceData: { ethnicities: any[]; languages: any[]; religions: any[]; regions: any[] };
}) {
  const [data, setData] = useState<DemographicData>({ regionCode: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();
  const isRTL = locale === "ar" || locale === "ku";

  const update = (field: keyof DemographicData, value: any) =>
    setData((prev) => ({ ...prev, [field]: value }));

  const submit = async () => {
    if (!data.regionCode) {
      setError(locale === "ar" ? "الرجاء تحديد المنطقة" : "Please select your region");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/v1/census/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          zkp_proof: zkpData.proof,
          nullifier_hash: zkpData.nullifier,
          region_code: data.regionCode,
          district_code: data.districtCode,
          is_urban: data.isUrban,
          ethnicity_code: data.ethnicityCode,
          language_code: data.languageCode,
          religion_code: data.religionCode,
          age_bracket: data.ageBracket,
          gender_code: data.genderCode,
          household_size: data.householdSize,
          education_level: data.educationLevel,
          employment_status: data.employmentStatus,
          housing_type: data.housingType,
        }),
      });

      if (!res.ok) {
        const d = await res.json();
        setError(d.detail || "Submission failed");
        return;
      }

      const d = await res.json();
      onSubmitted(d.confirmation_code);
    } catch {
      // Offline: save locally
      saveOffline(data, zkpData);
      onSubmitted("OFFLINE-PENDING");
    } finally {
      setLoading(false);
    }
  };

  const saveOffline = (formData: DemographicData, zkp: any) => {
    const pending = JSON.parse(localStorage.getItem("census_pending") || "[]");
    pending.push({ formData, zkp, savedAt: Date.now() });
    localStorage.setItem("census_pending", JSON.stringify(pending));
  };

  const SelectField = ({ label, field, options }: { label: string; field: keyof DemographicData; options: { code: string; label: string }[] }) => (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">{label}</label>
      <select
        value={(data[field] as string) || ""}
        onChange={(e) => update(field, e.target.value || undefined)}
        className="w-full px-4 py-3 border border-gray-300 rounded-lg bg-white focus:ring-2 focus:ring-blue-500"
      >
        <option value="">{locale === "ar" ? "اختر..." : "Select..."}</option>
        {options.map((opt) => (
          <option key={opt.code} value={opt.code}>{opt.label}</option>
        ))}
      </select>
    </div>
  );

  return (
    <div className="space-y-8" dir={isRTL ? "rtl" : "ltr"}>
      <div>
        <h2 className="text-2xl font-bold text-gray-900">
          {locale === "ar" ? "استمارة التعداد السكاني" : "Census Form"}
        </h2>
        <p className="mt-2 text-sm text-gray-600">
          {locale === "ar"
            ? "جميع البيانات طوعية وسرية تمامًا. لا يمكن ربطها بهويتك."
            : "All data is voluntary and completely confidential. It cannot be linked to your identity."}
        </p>
      </div>

      <div className="space-y-6">
        <h3 className="text-lg font-semibold text-gray-800 border-b pb-2">
          {locale === "ar" ? "الموقع الجغرافي" : "Location"}
        </h3>

        <SelectField
          label={locale === "ar" ? "المحافظة / المنطقة *" : "Province / Region *"}
          field="regionCode"
          options={referenceData.regions.map((r) => ({
            code: r.code,
            label: locale === "ar" ? r.name_local : r.name_en,
          }))}
        />

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            {locale === "ar" ? "نوع المنطقة السكنية" : "Settlement type"}
          </label>
          <div className="grid grid-cols-2 gap-3">
            {[{ v: true, ar: "حضري", en: "Urban" }, { v: false, ar: "ريفي", en: "Rural" }].map(({ v, ar, en }) => (
              <button
                key={String(v)}
                onClick={() => update("isUrban", v)}
                className={`py-3 px-4 rounded-lg border-2 text-sm font-medium transition-colors ${
                  data.isUrban === v
                    ? "border-blue-500 bg-blue-50 text-blue-700"
                    : "border-gray-200 bg-white text-gray-600"
                }`}
              >
                {locale === "ar" ? ar : en}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="space-y-6">
        <h3 className="text-lg font-semibold text-gray-800 border-b pb-2">
          {locale === "ar" ? "المعلومات الديموغرافية" : "Demographic Information"}
        </h3>

        <SelectField
          label={locale === "ar" ? "الفئة العمرية" : "Age group"}
          field="ageBracket"
          options={AGE_BRACKETS.map((b) => ({ code: b.code, label: locale === "ar" ? b.label_ar : b.label_en }))}
        />

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            {locale === "ar" ? "الجنس" : "Gender"}
          </label>
          <div className="grid grid-cols-3 gap-3">
            {[
              { code: "male", ar: "ذكر", en: "Male" },
              { code: "female", ar: "أنثى", en: "Female" },
              { code: "prefer_not", ar: "أفضل عدم الإفصاح", en: "Prefer not to say" },
            ].map(({ code, ar, en }) => (
              <button
                key={code}
                onClick={() => update("genderCode", code)}
                className={`py-3 px-2 rounded-lg border-2 text-sm font-medium transition-colors ${
                  data.genderCode === code
                    ? "border-blue-500 bg-blue-50 text-blue-700"
                    : "border-gray-200 bg-white text-gray-600"
                }`}
              >
                {locale === "ar" ? ar : en}
              </button>
            ))}
          </div>
        </div>

        <SelectField
          label={locale === "ar" ? "القومية / الإثنية" : "Ethnicity"}
          field="ethnicityCode"
          options={referenceData.ethnicities.map((e) => ({
            code: e.code,
            label: locale === "ar" ? e.name_local : e.name_en,
          }))}
        />

        <SelectField
          label={locale === "ar" ? "اللغة الأم" : "Mother tongue"}
          field="languageCode"
          options={referenceData.languages.map((l) => ({
            code: l.code,
            label: locale === "ar" ? l.name_local : l.name_en,
          }))}
        />

        <SelectField
          label={locale === "ar" ? "الديانة" : "Religion"}
          field="religionCode"
          options={referenceData.religions.map((r) => ({
            code: r.code,
            label: locale === "ar" ? r.name_local : r.name_en,
          }))}
        />
      </div>

      <div className="space-y-6">
        <h3 className="text-lg font-semibold text-gray-800 border-b pb-2">
          {locale === "ar" ? "المعلومات الاجتماعية والاقتصادية" : "Socioeconomic Information"}
        </h3>

        <SelectField
          label={locale === "ar" ? "المستوى التعليمي" : "Education level"}
          field="educationLevel"
          options={EDUCATION_LEVELS.map((e) => ({
            code: e.code,
            label: locale === "ar" ? e.label_ar : e.label_en,
          }))}
        />

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            {locale === "ar" ? "حجم الأسرة (عدد الأفراد)" : "Household size"}
          </label>
          <input
            type="number"
            min={1}
            max={30}
            value={data.householdSize || ""}
            onChange={(e) => update("householdSize", parseInt(e.target.value) || undefined)}
            className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
            dir="ltr"
          />
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          {error}
        </div>
      )}

      <button
        onClick={submit}
        disabled={loading || !data.regionCode}
        className="w-full py-5 bg-green-600 text-white text-lg font-semibold rounded-xl hover:bg-green-700 disabled:opacity-50 transition-colors"
      >
        {loading
          ? (locale === "ar" ? "جاري الإرسال..." : "Submitting...")
          : (locale === "ar" ? "إرسال استمارة التعداد" : "Submit Census Form")}
      </button>

      <p className="text-center text-xs text-gray-400">
        {locale === "ar"
          ? "جميع المعلومات طوعية. يمكنك تخطي أي سؤال."
          : "All information is voluntary. You may skip any question."}
      </p>
    </div>
  );
}

// ─── Main Page Component ──────────────────────────────────────────────────────

export default function CensusPage() {
  const [step, setStep] = useState<VerificationStep>("otp");
  const [locale, setLocale] = useState("ar");
  const [confirmationCode, setConfirmationCode] = useState<string>();
  const [zkpData, setZkpData] = useState<{ proof: string; nullifier: string }>();
  const [sessionToken, setSessionToken] = useState<string>();
  const [otpState, setOtpState] = useState<OTPState>({
    phoneNumber: "",
    channel: "sms",
    sent: false,
    verified: false,
  });

  // Mock reference data — in production loaded from /v1/reference
  const referenceData = {
    ethnicities: [
      { code: "arab", name_local: "عربي", name_en: "Arab" },
      { code: "kurd", name_local: "كردي", name_en: "Kurdish" },
      { code: "turkmen", name_local: "تركماني", name_en: "Turkmen" },
      { code: "syriac", name_local: "سرياني", name_en: "Syriac" },
      { code: "armenian", name_local: "أرمني", name_en: "Armenian" },
      { code: "other", name_local: "أخرى", name_en: "Other" },
    ],
    languages: [
      { code: "ara", name_local: "العربية", name_en: "Arabic" },
      { code: "ckb", name_local: "كردي سوراني", name_en: "Kurdish (Sorani)" },
      { code: "kmr", name_local: "كردي كرمانجي", name_en: "Kurdish (Kurmanji)" },
      { code: "tuk", name_local: "التركمانية", name_en: "Turkmen" },
      { code: "syr", name_local: "السريانية", name_en: "Syriac" },
    ],
    religions: [
      { code: "islam_sunni", name_local: "إسلام سني", name_en: "Islam (Sunni)" },
      { code: "islam_shia", name_local: "إسلام شيعي", name_en: "Islam (Shia)" },
      { code: "christianity", name_local: "مسيحية", name_en: "Christianity" },
      { code: "yazidi", name_local: "إيزيدية", name_en: "Yazidi" },
      { code: "mandaean", name_local: "مندائية", name_en: "Mandaean" },
      { code: "other", name_local: "أخرى", name_en: "Other" },
      { code: "prefer_not", name_local: "أفضل عدم الإفصاح", name_en: "Prefer not to say" },
    ],
    regions: [
      { code: "BG", name_local: "بغداد", name_en: "Baghdad" },
      { code: "BS", name_local: "البصرة", name_en: "Basra" },
      { code: "MO", name_local: "الموصل / نينوى", name_en: "Mosul / Nineveh" },
      { code: "ER", name_local: "أربيل", name_en: "Erbil" },
      { code: "SL", name_local: "السليمانية", name_en: "Sulaymaniyah" },
      { code: "KR", name_local: "كركوك", name_en: "Kirkuk" },
    ],
  };

  const STEPS = ["otp", "face", "census", "complete"];
  const stepIndex = STEPS.indexOf(step);
  const progress = ((stepIndex + 1) / STEPS.length) * 100;
  const isRTL = locale === "ar" || locale === "ku";

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50" dir={isRTL ? "rtl" : "ltr"}>
      {/* Header */}
      <header className="bg-white border-b border-gray-200 shadow-sm">
        <div className="max-w-2xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <span className="text-white text-lg">🏛</span>
            </div>
            <div>
              <h1 className="text-lg font-bold text-gray-900">
                {locale === "ar" ? "التعداد السكاني الوطني 2026" : "National Census 2026"}
              </h1>
              <p className="text-xs text-gray-500">
                {locale === "ar" ? "آمن • سري • مشفر" : "Secure • Confidential • Encrypted"}
              </p>
            </div>
          </div>
          <select
            value={locale}
            onChange={(e) => setLocale(e.target.value)}
            className="text-sm border border-gray-200 rounded-lg px-3 py-2"
          >
            <option value="ar">العربية</option>
            <option value="ku">کوردی</option>
            <option value="en">English</option>
          </select>
        </div>
      </header>

      {/* Progress Bar */}
      {step !== "complete" && (
        <div className="bg-white border-b">
          <div className="max-w-2xl mx-auto px-4 py-3">
            <div className="flex items-center justify-between text-xs text-gray-500 mb-2">
              <span>{locale === "ar" ? `الخطوة ${stepIndex + 1} من ${STEPS.length - 1}` : `Step ${stepIndex + 1} of ${STEPS.length - 1}`}</span>
              <span>{Math.round(progress)}%</span>
            </div>
            <div className="w-full bg-gray-100 rounded-full h-2">
              <div
                className="bg-blue-600 h-2 rounded-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="max-w-2xl mx-auto px-4 py-8">
        <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 md:p-8">
          {step === "otp" && (
            <OTPStep
              state={otpState}
              onChange={setOtpState}
              onVerified={(token) => { setSessionToken(token); setStep("face"); }}
              locale={locale}
            />
          )}

          {step === "face" && sessionToken && (
            <FaceVerificationStep
              sessionToken={sessionToken}
              onVerified={(d) => { setZkpData({ proof: d.proof, nullifier: d.nullifier }); setStep("census"); }}
              locale={locale}
            />
          )}

          {step === "census" && zkpData && (
            <CensusFormStep
              zkpData={zkpData}
              onSubmitted={(code) => { setConfirmationCode(code); setStep("complete"); }}
              locale={locale}
              referenceData={referenceData}
            />
          )}

          {step === "complete" && (
            <div className="text-center space-y-6" dir={isRTL ? "rtl" : "ltr"}>
              <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mx-auto">
                <span className="text-4xl">✅</span>
              </div>
              <div>
                <h2 className="text-2xl font-bold text-gray-900">
                  {locale === "ar" ? "شكرًا لمشاركتك!" : "Thank you for participating!"}
                </h2>
                <p className="mt-2 text-gray-600">
                  {locale === "ar"
                    ? "تم تسجيل مشاركتك في التعداد السكاني بنجاح."
                    : "Your census participation has been recorded successfully."}
                </p>
              </div>
              <div className="bg-gray-50 border border-gray-200 rounded-xl p-4">
                <p className="text-sm text-gray-500 mb-1">
                  {locale === "ar" ? "رمز التأكيد" : "Confirmation code"}
                </p>
                <p className="text-2xl font-mono font-bold text-gray-900 tracking-wider">
                  {confirmationCode}
                </p>
                <p className="text-xs text-gray-400 mt-2">
                  {locale === "ar"
                    ? "احتفظ بهذا الرمز لإثبات مشاركتك إن احتجت لذلك"
                    : "Keep this code to prove your participation if needed"}
                </p>
              </div>
              <div className="p-4 bg-blue-50 rounded-lg text-blue-700 text-sm">
                {locale === "ar"
                  ? "🔒 بياناتك محمية: لا يمكن لأحد ربط إجاباتك بهويتك، حتى الجهات الحكومية."
                  : "🔒 Your data is protected: No one can link your answers to your identity, including government authorities."}
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="max-w-2xl mx-auto px-4 py-6 text-center text-xs text-gray-400">
        <p>
          {locale === "ar"
            ? "محمي بتشفير AES-256 وإثبات المعرفة الصفرية (ZKP) • ISO 27001"
            : "Protected by AES-256 encryption and Zero-Knowledge Proofs • ISO 27001"}
        </p>
      </footer>
    </div>
  );
}
