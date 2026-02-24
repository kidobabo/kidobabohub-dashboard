const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
const { setGlobalOptions } = require("firebase-functions/v2");
const logger = require("firebase-functions/logger");
const admin = require("firebase-admin");
const crypto = require("crypto");

// ✅ Secrets (modern config replacement)
const { defineSecret } = require("firebase-functions/params");
const PAYSTACK_SECRET_KEY = defineSecret("PAYSTACK_SECRET_KEY");

admin.initializeApp();
const db = admin.firestore();

// Keep all functions in same region
setGlobalOptions({ region: "europe-west1" });

/** ===========================
 * Helpers
 * =========================== */

function randCode(len = 6) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function randToken(len = 32) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function requireAuth(req) {
  if (!req.auth) throw new HttpsError("unauthenticated", "Please login first.");
  return req.auth.uid;
}

async function getUser(uid) {
  const snap = await db.collection("users").doc(uid).get();
  return snap.exists ? snap.data() : null;
}

function nowTS() {
  return admin.firestore.FieldValue.serverTimestamp();
}

async function requireOrg(uid) {
  const me = await getUser(uid);
  if (!me?.orgId) throw new HttpsError("failed-precondition", "No org. Join or create a school first.");
  return me;
}

async function requireLinkedChild(uid, studentId) {
  const linkDoc = await db.collection("users").doc(uid).collection("children").doc(studentId).get();
  if (!linkDoc.exists) throw new HttpsError("permission-denied", "Not linked to this child.");
  return linkDoc.data();
}

function tsToMillis(ts) {
  try {
    if (!ts) return 0;
    if (ts.toMillis) return ts.toMillis();
    if (ts.seconds) return ts.seconds * 1000;
    if (ts._seconds) return ts._seconds * 1000;
  } catch (_) {}
  return 0;
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function timingSafeEqualHex(a, b) {
  try {
    const aa = Buffer.from(String(a || ""), "hex");
    const bb = Buffer.from(String(b || ""), "hex");
    if (aa.length !== bb.length) return false;
    return crypto.timingSafeEqual(aa, bb);
  } catch (_) {
    return false;
  }
}

async function paystackApi(secret, path, bodyObj) {
  // Node 20 runtime supports global fetch in Cloud Functions v2
  const url = `https://api.paystack.co${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(bodyObj || {}),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || data?.status === false) {
    const msg = data?.message || `Paystack error (${res.status})`;
    throw new Error(msg);
  }
  return data;
}

/** ===========================
 * ✅ PAYSTACK WEBHOOK (Auto-activate after payment)
 * Webhook URL:
 * https://europe-west1-kidobabohub.cloudfunctions.net/paystackWebhook
 * =========================== */
exports.paystackWebhook = onRequest(
  {
    cors: false,
    secrets: [PAYSTACK_SECRET_KEY],
  },
  async (req, res) => {
    try {
      if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

      const secret = PAYSTACK_SECRET_KEY.value();
      if (!secret) return res.status(500).send("Missing secret");

      const signature = req.get("x-paystack-signature");
      if (!signature) return res.status(400).send("Missing signature");

      // Paystack signs the raw body (Buffer). If rawBody missing, fallback safely.
      const raw = req.rawBody ? req.rawBody : Buffer.from(JSON.stringify(req.body || {}));

      const computedHash = crypto.createHmac("sha512", secret).update(raw).digest("hex");

      // timing-safe compare
      if (!timingSafeEqualHex(computedHash, signature)) return res.status(400).send("Invalid signature");

      const event = req.body;

      if (event?.event !== "charge.success") return res.status(200).send("Ignored");

      const data = event.data || {};
      const reference = data.reference || null;
      const email = normalizeEmail(data.customer?.email || null);
      const amount = Number(data.amount || 0); // integer subunits

      if (!email) return res.status(200).send("No email");

      // Prevent duplicate processing (by reference)
      if (reference) {
        const refDoc = db.collection("paystack_events").doc(reference);
        const exists = await refDoc.get();
        if (exists.exists) return res.status(200).send("Duplicate");
        await refDoc.set({
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          email,
          amount,
        });
      }

      // ✅ Your KES prices (subunits *100)
      const AMT_MONTHLY = 100 * 100;     // 10000
      const AMT_YEARLY = 900 * 100;      // 90000
      const AMT_LIFETIME = 5000 * 100;   // 500000
      const AMT_COMMUNITY = 5 * 100;     // 500

      // Prefer metadata plan if available (more reliable than amount)
      const metaPlan = String(data.metadata?.plan || "").trim().toLowerCase();

      let plan = "pending";
      let days = null;

      if (metaPlan) {
        if (["monthly", "yearly", "lifetime", "community"].includes(metaPlan)) {
          plan = metaPlan;
          days = metaPlan === "monthly" ? 30 : metaPlan === "yearly" ? 365 : null;
        }
      } else {
        if (amount === AMT_MONTHLY) { plan = "monthly"; days = 30; }
        else if (amount === AMT_YEARLY) { plan = "yearly"; days = 365; }
        else if (amount === AMT_LIFETIME) { plan = "lifetime"; days = null; }
        else if (amount === AMT_COMMUNITY) { plan = "community"; days = null; }
      }

      // Match Firebase user doc by email
      const userSnap = await db.collection("users").where("email", "==", email).limit(1).get();
      if (userSnap.empty) {
        logger.warn("No matching user for email:", email);
        return res.status(200).send("No matching user");
      }

      const userRef = userSnap.docs[0].ref;

      const updates = {
        plan,
        status: plan === "pending" ? "inactive" : "active",
        lastPaymentRef: reference || null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        trialEndsAt: null,
      };

      if (days) {
        updates.subscriptionEndsAt = admin.firestore.Timestamp.fromDate(
          new Date(Date.now() + days * 24 * 60 * 60 * 1000)
        );
      } else {
        updates.subscriptionEndsAt = null; // lifetime/community
      }

      await userRef.set(updates, { merge: true });

      logger.info("Paystack activated:", { email, plan, amount, reference });
      return res.status(200).send("OK");
    } catch (e) {
      logger.error("paystackWebhook error:", e);
      return res.status(500).send("Server error");
    }
  }
);

/** ===========================
 * ✅ NEW: Create Paystack checkout link (solves PAY_URL problem)
 * Frontend can call this and open authorization_url.
 *
 * Usage from your pay.html / subscription.js:
 * firebase.functions().httpsCallable("initPaystackCheckout")({ plan: "monthly", next: "/studentsdashboard.html" })
 * =========================== */
exports.initPaystackCheckout = onCall(
  {
    secrets: [PAYSTACK_SECRET_KEY],
  },
  async (req) => {
    const uid = requireAuth(req);

    const me = await getUser(uid);
    const email = normalizeEmail(me?.email || req.auth?.token?.email || "");
    if (!email) throw new HttpsError("failed-precondition", "No email found on this account.");

    const plan = String(req.data?.plan || "monthly").trim().toLowerCase();
    const next = String(req.data?.next || "/studentsdashboard.html").trim();

    // Match your webhook amounts (subunits *100)
    const PRICES = {
      monthly: 100 * 100,
      yearly: 900 * 100,
      lifetime: 5000 * 100,
      community: 5 * 100,
    };

    if (!PRICES[plan]) throw new HttpsError("invalid-argument", "Invalid plan.");

    const secret = PAYSTACK_SECRET_KEY.value();
    if (!secret) throw new HttpsError("internal", "Missing PAYSTACK_SECRET_KEY.");

    // Optional: create your own reference
    const reference = `KBH_${Date.now().toString(36)}_${randCode(6)}`;

    // Where Paystack sends the user after payment (webhook still activates)
    const callback_url = `https://kidobabohub.web.app/pay.html?next=${encodeURIComponent(next)}`;

    const payload = {
      email,
      amount: PRICES[plan],
      reference,
      callback_url,
      metadata: {
        plan,
        uid,
        next,
        app: "kidobabohub",
      },
    };

    try {
      const data = await paystackApi(secret, "/transaction/initialize", payload);
      const authUrl = data?.data?.authorization_url;
      if (!authUrl) throw new Error("No authorization_url returned.");

      return { ok: true, authorization_url: authUrl, reference };
    } catch (e) {
      logger.error("initPaystackCheckout error:", e);
      throw new HttpsError("internal", e?.message || "Paystack initialize failed.");
    }
  }
);

/** ===========================
 * ORG + MEMBERS
 * =========================== */

exports.createOrgAndAdmin = onCall(async (req) => {
  const uid = requireAuth(req);
  const orgName = (req.data?.orgName || "").trim();
  const name = (req.data?.name || "").trim();
  if (!orgName) throw new HttpsError("invalid-argument", "orgName is required.");

  const orgId = "org_" + Date.now().toString(36) + "_" + randCode(4);
  let joinCode = randCode(6);

  for (let i = 0; i < 8; i++) {
    const q = await db.collection("orgs").where("joinCode", "==", joinCode).limit(1).get();
    if (q.empty) break;
    joinCode = randCode(6);
  }

  await db.collection("orgs").doc(orgId).set({
    orgId,
    name: orgName,
    joinCode,
    ownerUid: uid,
    createdAt: nowTS(),
  });

  await db.collection("users").doc(uid).set(
    {
      uid,
      name: name || req.auth?.token?.name || "",
      email: normalizeEmail(req.auth?.token?.email || ""),
      role: "admin",
      orgId,
      createdAt: nowTS(),
      updatedAt: nowTS(),
    },
    { merge: true }
  );

  await db.collection("orgs").doc(orgId).collection("members").doc(uid).set(
    {
      uid,
      role: "admin",
      name: name || req.auth?.token?.name || "",
      email: normalizeEmail(req.auth?.token?.email || ""),
      createdAt: nowTS(),
    },
    { merge: true }
  );

  return { ok: true, orgId, joinCode };
});

exports.joinOrgWithCode = onCall(async (req) => {
  const uid = requireAuth(req);
  const joinCode = (req.data?.joinCode || "").trim().toUpperCase();
  const role = (req.data?.role || "").trim();
  const name = (req.data?.name || "").trim();

  if (!joinCode) throw new HttpsError("invalid-argument", "joinCode is required.");
  if (!["teacher", "parent"].includes(role)) {
    throw new HttpsError("invalid-argument", "role must be teacher or parent.");
  }

  const orgQ = await db.collection("orgs").where("joinCode", "==", joinCode).limit(1).get();
  if (orgQ.empty) throw new HttpsError("not-found", "Join code not found.");

  const orgId = orgQ.docs[0].id;

  await db.collection("users").doc(uid).set(
    {
      uid,
      name: name || req.auth?.token?.name || "",
      email: normalizeEmail(req.auth?.token?.email || ""),
      role,
      orgId,
      updatedAt: nowTS(),
      createdAt: nowTS(),
    },
    { merge: true }
  );

  await db.collection("orgs").doc(orgId).collection("members").doc(uid).set(
    {
      uid,
      role,
      name: name || req.auth?.token?.name || "",
      email: normalizeEmail(req.auth?.token?.email || ""),
      createdAt: nowTS(),
    },
    { merge: true }
  );

  return { ok: true, orgId, role };
});

/** ===========================
 * STUDENTS + PARENT LINKS
 * =========================== */

exports.createStudent = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);
  if (!["admin", "teacher"].includes(me.role)) {
    throw new HttpsError("permission-denied", "Only admin/teacher can add students.");
  }

  const name = (req.data?.name || "").trim();
  const className = (req.data?.className || "PP1").trim();
  const age = Number(req.data?.age || 4);
  if (!name) throw new HttpsError("invalid-argument", "Student name required.");

  const studentCode = "KIDO-" + randCode(6);
  const stRef = db.collection("orgs").doc(me.orgId).collection("students").doc();

  await stRef.set({
    orgId: me.orgId,
    studentId: stRef.id,
    name,
    className,
    age,
    studentCode,
    createdAt: nowTS(),
    createdBy: uid,
  });

  return { ok: true, studentId: stRef.id, studentCode };
});

exports.listStudents = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);
  if (!["admin", "teacher"].includes(me.role)) {
    throw new HttpsError("permission-denied", "Only admin/teacher can list students.");
  }

  const snap = await db.collection("orgs").doc(me.orgId).collection("students").limit(500).get();
  const students = snap.docs.map((d) => d.data());
  students.sort((a, b) =>
    String(a.name || "").toLowerCase().localeCompare(String(b.name || "").toLowerCase())
  );
  return { ok: true, orgId: me.orgId, students };
});

exports.linkChildByCode = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);
  if (me.role !== "parent") throw new HttpsError("permission-denied", "Only parents can link a child.");

  const code = (req.data?.studentCode || "").trim().toUpperCase();
  if (!code) throw new HttpsError("invalid-argument", "studentCode required.");

  const stSnap = await db
    .collection("orgs")
    .doc(me.orgId)
    .collection("students")
    .where("studentCode", "==", code)
    .limit(1)
    .get();

  if (stSnap.empty) throw new HttpsError("not-found", "Child code not found in your school.");

  const student = stSnap.docs[0].data();
  const studentId = student.studentId || stSnap.docs[0].id;

  await db.collection("users").doc(uid).collection("children").doc(studentId).set(
    {
      orgId: me.orgId,
      studentId,
      studentName: student.name || "",
      className: student.className || "",
      linkedAt: nowTS(),
    },
    { merge: true }
  );

  return { ok: true, studentId, student };
});

exports.listMyChildren = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);
  if (me.role !== "parent") throw new HttpsError("permission-denied", "Only parents can list children.");

  const snap = await db.collection("users").doc(uid).collection("children").limit(50).get();
  const children = snap.docs.map((d) => d.data());
  children.sort((a, b) => String(a.studentName || "").localeCompare(String(b.studentName || "")));
  return { ok: true, children };
});

/** ===========================
 * SCORES + NOTES + REPORT
 * =========================== */

exports.addScore = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);
  if (!["admin", "teacher"].includes(me.role)) {
    throw new HttpsError("permission-denied", "Only admin/teacher can add scores.");
  }

  const studentId = (req.data?.studentId || "").trim();
  const subject = (req.data?.subject || "Math").trim();
  const score = Number(req.data?.score);
  const note = (req.data?.note || "").trim();

  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");
  if (Number.isNaN(score) || score < 0 || score > 100) {
    throw new HttpsError("invalid-argument", "score must be 0-100.");
  }

  const stDoc = await db.collection("orgs").doc(me.orgId).collection("students").doc(studentId).get();
  if (!stDoc.exists) throw new HttpsError("not-found", "Student not found.");
  const student = stDoc.data();

  await db.collection("orgs").doc(me.orgId).collection("scores").add({
    orgId: me.orgId,
    studentId,
    studentName: student?.name || "",
    className: student?.className || "",
    subject,
    score,
    note,
    createdBy: uid,
    createdByRole: me.role || "",
    createdAt: nowTS(),
  });

  return { ok: true };
});

exports.listScoresForStudent = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);

  const studentId = (req.data?.studentId || "").trim();
  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");

  if (me.role === "parent") {
    await requireLinkedChild(uid, studentId);
  }

  const snap = await db
    .collection("orgs")
    .doc(me.orgId)
    .collection("scores")
    .where("studentId", "==", studentId)
    .limit(500)
    .get();

  const rows = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  rows.sort((a, b) => (b.createdAt?.toMillis?.() || 0) - (a.createdAt?.toMillis?.() || 0));
  return { ok: true, rows };
});

exports.sendNote = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);
  if (!["admin", "teacher"].includes(me.role)) {
    throw new HttpsError("permission-denied", "Only admin/teacher can send notes.");
  }

  const studentId = (req.data?.studentId || "").trim();
  const title = (req.data?.title || "").trim();
  const message = (req.data?.message || "").trim();

  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");
  if (!message) throw new HttpsError("invalid-argument", "message required.");

  const safeTitle = title || "Teacher Note";

  const stDoc = await db.collection("orgs").doc(me.orgId).collection("students").doc(studentId).get();
  if (!stDoc.exists) throw new HttpsError("not-found", "Student not found.");
  const student = stDoc.data();

  await db.collection("orgs").doc(me.orgId).collection("notes").add({
    orgId: me.orgId,
    studentId,
    studentName: student?.name || "",
    className: student?.className || "",
    title: safeTitle,
    message,
    fromUid: uid,
    fromRole: me.role,
    fromName: me.name || "",
    createdAt: nowTS(),
  });

  return { ok: true };
});

exports.listNotesForStudent = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);

  const studentId = (req.data?.studentId || "").trim();
  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");

  if (me.role === "parent") {
    await requireLinkedChild(uid, studentId);
  }

  const snap = await db
    .collection("orgs")
    .doc(me.orgId)
    .collection("notes")
    .where("studentId", "==", studentId)
    .limit(200)
    .get();

  const rows = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  rows.sort((a, b) => (b.createdAt?.toMillis?.() || 0) - (a.createdAt?.toMillis?.() || 0));
  return { ok: true, rows };
});

exports.getStudentReportData = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);

  const studentId = (req.data?.studentId || "").trim();
  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");

  if (me.role === "parent") {
    await requireLinkedChild(uid, studentId);
  }

  const stDoc = await db.collection("orgs").doc(me.orgId).collection("students").doc(studentId).get();
  if (!stDoc.exists) throw new HttpsError("not-found", "Student not found.");

  const student = stDoc.data();

  const scoresSnap = await db
    .collection("orgs")
    .doc(me.orgId)
    .collection("scores")
    .where("studentId", "==", studentId)
    .limit(500)
    .get();

  const notesSnap = await db
    .collection("orgs")
    .doc(me.orgId)
    .collection("notes")
    .where("studentId", "==", studentId)
    .limit(200)
    .get();

  const scores = scoresSnap.docs.map((d) => d.data());
  const notes = notesSnap.docs.map((d) => d.data());

  scores.sort((a, b) => (b.createdAt?.toMillis?.() || 0) - (a.createdAt?.toMillis?.() || 0));
  notes.sort((a, b) => (b.createdAt?.toMillis?.() || 0) - (a.createdAt?.toMillis?.() || 0));

  return { ok: true, orgId: me.orgId, student, scores, notes };
});

/** ===========================
 * ⭐ Rewards / Stars
 * =========================== */

exports.addRewardStar = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);

  if (!["admin", "teacher"].includes(me.role)) {
    throw new HttpsError("permission-denied", "Only admin/teacher can add reward stars.");
  }

  const studentId = (req.data?.studentId || "").trim();
  const reason = (req.data?.reason || "").trim();

  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");

  const stDoc = await db.collection("orgs").doc(me.orgId).collection("students").doc(studentId).get();
  if (!stDoc.exists) throw new HttpsError("not-found", "Student not found.");
  const student = stDoc.data();

  await db.collection("orgs").doc(me.orgId).collection("rewards").add({
    orgId: me.orgId,
    studentId,
    studentName: student?.name || "",
    className: student?.className || "",
    reason,
    createdBy: uid,
    createdByRole: me.role || "",
    createdAt: nowTS(),
  });

  return { ok: true };
});

exports.getRewardsForStudent = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);

  const studentId = (req.data?.studentId || "").trim();
  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");

  if (me.role === "parent") {
    await requireLinkedChild(uid, studentId);
  } else if (!["admin", "teacher"].includes(me.role)) {
    throw new HttpsError("permission-denied", "Not allowed.");
  }

  const snap = await db
    .collection("orgs")
    .doc(me.orgId)
    .collection("rewards")
    .where("studentId", "==", studentId)
    .limit(2000)
    .get();

  const totalStars = snap.size;

  let lastStarAt = null;
  snap.docs.forEach((d) => {
    const r = d.data();
    const t = r.createdAt?.toMillis?.() || 0;
    if (!lastStarAt || t > (lastStarAt?.toMillis?.() || 0)) lastStarAt = r.createdAt || null;
  });

  return { ok: true, totalStars, lastStarAt };
});

/** ===========================
 * 📊 Analytics
 * =========================== */

exports.getStudentAnalytics = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);

  const studentId = (req.data?.studentId || "").trim();
  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");

  if (me.role === "parent") {
    await requireLinkedChild(uid, studentId);
  } else if (!["admin", "teacher"].includes(me.role)) {
    throw new HttpsError("permission-denied", "Not allowed.");
  }

  const snap = await db
    .collection("orgs")
    .doc(me.orgId)
    .collection("scores")
    .where("studentId", "==", studentId)
    .limit(2000)
    .get();

  const rows = snap.docs.map((d) => d.data());

  let total = 0;
  let count = 0;
  const bySubject = {};

  rows.forEach((r) => {
    const s = Number(r.score);
    if (Number.isNaN(s)) return;

    count += 1;
    total += s;

    const subject = (r.subject || "Unknown").trim() || "Unknown";
    if (!bySubject[subject]) bySubject[subject] = { sum: 0, count: 0, avg: 0 };

    bySubject[subject].sum += s;
    bySubject[subject].count += 1;
  });

  Object.keys(bySubject).forEach((k) => {
    const obj = bySubject[k];
    obj.avg = obj.count ? Math.round((obj.sum / obj.count) * 10) / 10 : 0;
    delete obj.sum;
  });

  const avgScore = count ? Math.round((total / count) * 10) / 10 : 0;

  return { ok: true, studentId, totalScores: count, avgScore, bySubject };
});

/** ===========================
 * 📍 Location Tracking (Simple)
 * =========================== */

exports.saveChildLocation = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);

  const studentId = (req.data?.studentId || "").trim();
  const lat = Number(req.data?.lat);
  const lng = Number(req.data?.lng);
  const accuracy = Number(req.data?.accuracy || 0);

  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");
  if (Number.isNaN(lat) || Number.isNaN(lng)) throw new HttpsError("invalid-argument", "lat/lng required.");
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180) throw new HttpsError("invalid-argument", "lat/lng invalid.");

  if (me.role === "parent") {
    await requireLinkedChild(uid, studentId);
  } else if (!["admin", "teacher"].includes(me.role)) {
    throw new HttpsError("permission-denied", "Not allowed.");
  }

  const ref = db.collection("orgs").doc(me.orgId).collection("locations").doc(studentId);

  await ref.set(
    {
      orgId: me.orgId,
      studentId,
      lat,
      lng,
      accuracy,
      savedByUid: uid,
      savedByRole: me.role || "",
      createdAt: nowTS(),
    },
    { merge: true }
  );

  return { ok: true };
});

exports.getLastChildLocation = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);

  const studentId = (req.data?.studentId || "").trim();
  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");

  if (me.role === "parent") {
    await requireLinkedChild(uid, studentId);
  } else if (!["admin", "teacher"].includes(me.role)) {
    throw new HttpsError("permission-denied", "Not allowed.");
  }

  const ref = db.collection("orgs").doc(me.orgId).collection("locations").doc(studentId);
  const snap = await ref.get();

  if (!snap.exists) return { ok: true, location: null };
  return { ok: true, location: snap.data() };
});

/** ===========================
 * 📍 GPS TRACKING (Advanced)
 * =========================== */

exports.createTrackingSession = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);

  const studentId = (req.data?.studentId || "").trim();
  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");

  if (me.role === "parent") {
    await requireLinkedChild(uid, studentId);
  } else if (!["admin", "teacher"].includes(me.role)) {
    throw new HttpsError("permission-denied", "Only admin/teacher/parent can create tracking sessions.");
  }

  const stDoc = await db.collection("orgs").doc(me.orgId).collection("students").doc(studentId).get();
  if (!stDoc.exists) throw new HttpsError("not-found", "Student not found.");
  const student = stDoc.data();

  const sessionId = "SID_" + Date.now().toString(36) + "_" + randCode(5);
  const token = randToken(32);

  const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + 24 * 60 * 60 * 1000); // 24h
  await db.collection("orgs").doc(me.orgId).collection("trackingSessions").doc(sessionId).set({
    sessionId,
    token,
    orgId: me.orgId,
    studentId,
    studentName: student?.name || "",
    createdBy: uid,
    createdByRole: me.role || "",
    createdAt: nowTS(),
    expiresAt,
    isActive: true,
  });

  const base = "https://kidobabohub.web.app/tracker.html";
  const trackerUrl = `${base}#sid=${encodeURIComponent(sessionId)}&tok=${encodeURIComponent(token)}`;

  return { ok: true, sessionId, trackerUrl, expiresAt: expiresAt.toDate().toISOString() };
});

exports.trackPing = onRequest({ cors: true }, async (req, res) => {
  try {
    if (req.method !== "POST") {
      res.status(405).json({ ok: false, error: "POST only" });
      return;
    }

    const body = req.body || {};
    const sid = String(body.sid || "").trim();
    const tok = String(body.tok || "").trim();
    const lat = Number(body.lat);
    const lng = Number(body.lng);
    const acc = Number(body.acc || 0);

    if (!sid || !tok) {
      res.status(400).json({ ok: false, error: "sid and tok required" });
      return;
    }
    if (Number.isNaN(lat) || Number.isNaN(lng)) {
      res.status(400).json({ ok: false, error: "lat/lng invalid" });
      return;
    }

    const q = await db.collectionGroup("trackingSessions").where("sessionId", "==", sid).limit(1).get();
    if (q.empty) {
      res.status(404).json({ ok: false, error: "session not found" });
      return;
    }

    const sess = q.docs[0].data();

    if (!sess?.isActive) {
      res.status(403).json({ ok: false, error: "session inactive" });
      return;
    }
    if (String(sess.token || "") !== tok) {
      res.status(403).json({ ok: false, error: "bad token" });
      return;
    }
    const exp = tsToMillis(sess.expiresAt);
    if (exp && Date.now() > exp) {
      res.status(403).json({ ok: false, error: "session expired" });
      return;
    }

    const orgId = sess.orgId;
    const studentId = sess.studentId;

    const loc = {
      sid,
      orgId,
      studentId,
      lat,
      lng,
      acc,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      ua: String(req.headers["user-agent"] || "").slice(0, 180),
    };

    await db.collection("orgs").doc(orgId).collection("students").doc(studentId).collection("locations").add(loc);

    await db.collection("orgs").doc(orgId).collection("students").doc(studentId).set(
      {
        lastLocation: {
          lat,
          lng,
          acc,
          sid,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
      },
      { merge: true }
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

exports.getStudentLocation = onCall(async (req) => {
  const uid = requireAuth(req);
  const me = await requireOrg(uid);

  const studentId = (req.data?.studentId || "").trim();
  const limit = Math.min(50, Math.max(1, Number(req.data?.limit || 20)));
  if (!studentId) throw new HttpsError("invalid-argument", "studentId required.");

  if (me.role === "parent") {
    await requireLinkedChild(uid, studentId);
  } else if (!["admin", "teacher"].includes(me.role)) {
    throw new HttpsError("permission-denied", "Only admin/teacher/parent can view location.");
  }

  const stDoc = await db.collection("orgs").doc(me.orgId).collection("students").doc(studentId).get();
  if (!stDoc.exists) throw new HttpsError("not-found", "Student not found.");
  const student = stDoc.data() || {};

  const snap = await db
    .collection("orgs")
    .doc(me.orgId)
    .collection("students")
    .doc(studentId)
    .collection("locations")
    .orderBy("createdAt", "desc")
    .limit(limit)
    .get();

  const pings = snap.docs.map((d) => d.data());

  return {
    ok: true,
    student: { studentId, name: student.name || "", className: student.className || "" },
    lastLocation: student.lastLocation || null,
    pings,
  };
});