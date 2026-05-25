// ─────────────────────────────────────────────────────────────
//  Contact Form API  —  server.js
//  Production-safe Express backend for Renoweb contact form
// ─────────────────────────────────────────────────────────────

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const { Resend } = require("resend");
const { createClient } = require("@supabase/supabase-js");
const ws = require("ws");

// ── Config ──────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "";
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

const ALLOWED_SERVICES = [
  "lead-gen",
  "seo",
  "community",
  "performance",
  "multiple",
];

// ── Supabase client ─────────────────────────────────────────

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  realtime: {
    transport: ws,
  },
});

// ── Resend client ───────────────────────────────────────────

const resend = new Resend(RESEND_API_KEY);

// ── Express app ─────────────────────────────────────────────

const app = express();

// Global security headers
app.use(helmet());

// CORS — whitelist only the frontend origin
app.use(
  cors({
    origin: ALLOWED_ORIGIN,
    methods: ["POST"],
    allowedHeaders: ["Content-Type"],
  })
);

// Parse JSON bodies
app.use(express.json({ limit: "10kb" }));

// Rate limiter — 5 requests per IP per 15 minutes on /api/contact
const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error:
      "Too many submissions from this IP. Please try again after 15 minutes.",
  },
});

// ── Helpers ─────────────────────────────────────────────────

/**
 * Escapes HTML-special characters to prevent injection in email HTML.
 */
function escapeHtml(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Builds a clean HTML email body from validated & escaped fields.
 */
function buildEmailHtml(data) {
  const row = (label, value) =>
    value
      ? `<tr>
           <td style="padding:10px 16px;font-weight:600;color:#374151;border-bottom:1px solid #e5e7eb;white-space:nowrap;">${label}</td>
           <td style="padding:10px 16px;color:#1f2937;border-bottom:1px solid #e5e7eb;">${escapeHtml(value)}</td>
         </tr>`
      : "";

  return `
  <!DOCTYPE html>
  <html lang="en">
  <head><meta charset="UTF-8"></head>
  <body style="margin:0;padding:0;background:#f3f4f6;font-family:'Segoe UI',Arial,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:32px 0;">
      <tr><td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.06);">
          <!-- Header -->
          <tr>
            <td colspan="2" style="background:linear-gradient(135deg,#2563eb,#7c3aed);padding:28px 32px;">
              <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:700;">New Contact Form Submission</h1>
              <p style="margin:6px 0 0;color:rgba(255,255,255,0.85);font-size:14px;">A new enquiry has been received via the website.</p>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td colspan="2" style="padding:24px 32px 0;">
              <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
                ${row("Full Name", data.fullName)}
                ${row("Email", data.email)}
                ${row("Company", data.company)}
                ${row("Phone", data.phone)}
                ${row("Service", data.service)}
              </table>
            </td>
          </tr>
          <!-- Project Details -->
          <tr>
            <td colspan="2" style="padding:24px 32px;">
              <p style="margin:0 0 8px;font-weight:600;color:#374151;font-size:15px;">Project Details</p>
              <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:16px;color:#1f2937;font-size:14px;line-height:1.7;white-space:pre-wrap;">${escapeHtml(data.projectDetails)}</div>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td colspan="2" style="padding:16px 32px 24px;text-align:center;">
              <p style="margin:0;color:#9ca3af;font-size:12px;">This email was sent from the Renoweb contact form.</p>
            </td>
          </tr>
        </table>
      </td></tr>
    </table>
  </body>
  </html>`;
}

// ── Validation rules ────────────────────────────────────────

const contactValidation = [
  body("fullName")
    .trim()
    .notEmpty()
    .withMessage("Full name is required.")
    .isLength({ max: 100 })
    .withMessage("Full name must be 100 characters or fewer."),

  body("email")
    .trim()
    .notEmpty()
    .withMessage("Email is required.")
    .isEmail()
    .withMessage("Please provide a valid email address.")
    .normalizeEmail(),

  body("company")
    .optional({ values: "falsy" })
    .trim()
    .isLength({ max: 100 })
    .withMessage("Company must be 100 characters or fewer."),

  body("phone")
    .optional({ values: "falsy" })
    .trim()
    .isLength({ max: 20 })
    .withMessage("Phone must be 20 characters or fewer.")
    .matches(/^[0-9\s\-+]+$/)
    .withMessage("Phone may only contain digits, spaces, hyphens, and +."),

  body("service")
    .trim()
    .notEmpty()
    .withMessage("Service is required.")
    .isIn(ALLOWED_SERVICES)
    .withMessage(
      `Service must be one of: ${ALLOWED_SERVICES.join(", ")}.`
    ),

  body("projectDetails")
    .trim()
    .notEmpty()
    .withMessage("Project details are required.")
    .isLength({ max: 2000 })
    .withMessage("Project details must be 2000 characters or fewer."),
];

// ── Routes ──────────────────────────────────────────────────

// Health check
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Contact form submission
app.post(
  "/api/contact",
  contactLimiter,
  contactValidation,
  async (req, res) => {
    try {
      // ── Honeypot: silently discard bot submissions ──
      if (req.body._hp_url) {
        return res.json({
          success: true,
          message: "Your message has been sent successfully!",
        });
      }

      // ── Validation errors ──
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const messages = errors.array().map((e) => e.msg);
        return res.status(400).json({ success: false, error: messages.join(" ") });
      }

      // ── Extract validated fields only (ignore extra keys) ──
      const { fullName, email, company, phone, service, projectDetails } =
        req.body;

      const submission = {
        full_name: fullName,
        email,
        company: company || null,
        phone: phone || null,
        service,
        project_details: projectDetails,
        created_at: new Date().toISOString(),
      };

      // ── Run email + Supabase insert in parallel ──
      const [emailResult, dbResult] = await Promise.allSettled([
        // 1. Send email
        resend.emails.send({
          from: `${fullName} <growth@renowebhq.com>`,
          to: "samaresh.renoweb.webdevintern@gmail.com", // for testing now
          reply_to: email,
          subject: `New enquiry from ${fullName} — ${service}`,
          html: buildEmailHtml({ fullName, email, company, phone, service, projectDetails }),
        }),

        // 2. Store in Supabase
        supabase.from("contact_submissions").insert([submission]),
      ]);

      // Log failures server-side — never expose details to client
      if (emailResult.status === "rejected") {
        console.error("[EMAIL ERROR]", emailResult.reason);
      } else if (emailResult.value?.error) {
        console.error("[EMAIL ERROR]", emailResult.value.error);
      }
      if (dbResult.status === "rejected") {
        console.error("[SUPABASE ERROR]", dbResult.reason);
      } else if (dbResult.value?.error) {
        console.error("[SUPABASE ERROR]", dbResult.value.error);
      }

      // If both failed, return 500
      const emailOk = emailResult.status === "fulfilled" && !emailResult.value?.error;
      const dbOk =
        dbResult.status === "fulfilled" && !dbResult.value?.error;

      if (!emailOk && !dbOk) {
        return res.status(500).json({
          success: false,
          error:
            "We were unable to process your submission right now. Please try again later.",
        });
      }

      return res.json({
        success: true,
        message: "Your message has been sent successfully!",
      });
    } catch (err) {
      console.error("[UNHANDLED ERROR]", err);
      return res.status(500).json({
        success: false,
        error: "An unexpected error occurred. Please try again later.",
      });
    }
  }
);

// ── Start server ────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`✓ Contact Form API running on port ${PORT}`);
});
