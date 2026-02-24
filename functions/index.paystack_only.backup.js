/**
 * Firebase Functions (v2) + Paystack Webhook (secure)
 * - Uses Secrets Manager (PAYSTACK_SECRET_KEY)
 * - Verifies Paystack webhook signature (x-paystack-signature)
 * - Activates user subscription in Firestore by matching email
 */

const { setGlobalOptions } = require("firebase-functions/v2");
const { onRequest } = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");

const admin = require("firebase-admin");
const crypto = require("crypto");

// ✅ Secrets (modern replacement for functions.config)
const { defineSecret } = require("firebase-functions/params");
const PAYSTACK_SECRET_KEY = defineSecret("PAYSTACK_SECRET_KEY");

// Global options
setGlobalOptions({ maxInstances: 10 });

// Initialize Admin once
if (!admin.apps.length) {
  admin.initializeApp();
}

// ✅ Paystack webhook URL will be:
// https://europe-west1-kidobabohub.cloudfunctions.net/paystackWebhook
exports.paystackWebhook = onRequest(
  {
    region: "europe-west1",
    secrets: [PAYSTACK_SECRET_KEY],
  },
  async (req, res) => {
    try {
      if (req.method !== "POST") {
        return res.status(405).send("Method Not Allowed");
      }

      const secret = PAYSTACK_SECRET_KEY.value();
      if (!secret) {
        logger.error("Missing PAYSTACK_SECRET_KEY secret");
        return res.status(500).send("Missing secret");
      }

      // ✅ Verify Paystack signature (HMAC SHA512)
      // Paystack uses the raw request body for signing
      const signature = req.get("x-paystack-signature");
      if (!signature) return res.status(400).send("Missing signature");

      const rawBody = req.rawBody; // Buffer
      const computedHash = crypto
        .createHmac("sha512", secret)
        .update(rawBody)
        .digest("hex");

      if (computedHash !== signature) {
        logger.warn("Invalid Paystack signature");
        return res.status(400).send("Invalid signature");
      }

      const event = req.body;

      // Only handle successful charges
      if (event?.event !== "charge.success") {
        return res.status(200).send("Ignored");
      }

      const data = event.data || {};
      const reference = data.reference || null;
      const email = data.customer?.email || null;
      const amount = data.amount; // integer subunits

      if (!email) return res.status(200).send("No email");

      const db = admin.firestore();

      // Prevent double-processing same reference
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

      // ⚠️ Amount mapping assumption: KES uses *100 subunits
      // Monthly 100 => 10000
      // Yearly 900 => 90000
      // Lifetime 5000 => 500000
      // Community 5 => 500
      const AMT_MONTHLY = 100 * 100;
      const AMT_YEARLY = 900 * 100;
      const AMT_LIFETIME = 5000 * 100;
      const AMT_COMMUNITY = 5 * 100;

      let plan = "pending";
      let days = null;

      if (amount === AMT_MONTHLY) {
        plan = "monthly";
        days = 30;
      } else if (amount === AMT_YEARLY) {
        plan = "yearly";
        days = 365;
      } else if (amount === AMT_LIFETIME) {
        plan = "lifetime";
        days = null;
      } else if (amount === AMT_COMMUNITY) {
        plan = "community";
        days = null;
      }

      // Find user by email (your dashboard code stores email in users/{uid})
      const userSnap = await db
        .collection("users")
        .where("email", "==", email)
        .limit(1)
        .get();

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

      logger.info("Activated plan:", { email, plan, amount, reference });
      return res.status(200).send("OK");
    } catch (err) {
      logger.error("Webhook error:", err);
      return res.status(500).send("Server error");
    }
  }
);