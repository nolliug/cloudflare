const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=UTF-8" },
});

const text = (message, status) => new Response(message, {
  status,
  headers: { "content-type": "text/plain; charset=UTF-8" },
});

function clean(value, max) {
  return String(value ?? "").trim().replace(/[\r\n]/g, "").slice(0, max);
}

export async function onRequestPost({ request, env }) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/x-www-form-urlencoded") && !contentType.includes("multipart/form-data")) {
    return text("Unsupported content type.", 415);
  }

  const form = await request.formData();

  if (clean(form.get("website"), 200) !== "") {
    return text("Spam protection rejected the submission.", 400);
  }

  const name = clean(form.get("name"), 100);
  const email = clean(form.get("email"), 254);
  const subject = clean(form.get("subject"), 200);
  const message = String(form.get("message") ?? "").trim().slice(0, 5000);
  const captchaToken = clean(form.get("h-captcha-response"), 5000);

  if (!name || !subject || !message) return text("Please complete all required fields.", 400);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return text("Please enter a valid email address.", 400);
  if (!captchaToken) return text("Please complete the hCaptcha verification.", 400);

  if (!env.HCAPTCHA_SECRET || !env.RESEND_API_KEY || !env.CONTACT_TO || !env.MAIL_FROM) {
    console.error("Missing contact-form configuration.");
    return text("The contact form is not configured yet.", 500);
  }

  const captchaBody = new URLSearchParams({
    secret: env.HCAPTCHA_SECRET,
    response: captchaToken,
  });

  const remoteIp = request.headers.get("CF-Connecting-IP");
  if (remoteIp) captchaBody.set("remoteip", remoteIp);

  const captchaResponse = await fetch("https://api.hcaptcha.com/siteverify", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: captchaBody,
  });

  if (!captchaResponse.ok) {
    console.error("hCaptcha verification request failed", captchaResponse.status);
    return text("Spam verification is temporarily unavailable. Please try again later.", 502);
  }

  const captchaResult = await captchaResponse.json();
  if (!captchaResult.success) return text("Spam verification failed. Please try again.", 400);

  const mailText = [
    "New contact form submission",
    "",
    `Name: ${name}`,
    `Email: ${email}`,
    `Subject: ${subject}`,
    "",
    "Message:",
    message,
    "",
    `Submitted: ${new Date().toISOString()}`,
    `IP: ${remoteIp || "unknown"}`,
  ].join("\n");

  const resendResponse = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "authorization": `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: env.MAIL_FROM,
      to: [env.CONTACT_TO],
      reply_to: email,
      subject: `[Website contact] ${subject}`,
      text: mailText,
    }),
  });

  if (!resendResponse.ok) {
    console.error("Email delivery failed", resendResponse.status);
    return text("Your message could not be delivered. Please try again later.", 502);
  }

  return Response.redirect(new URL("/contact.html?sent=1", request.url), 303);
}

export async function onRequest(context) {
  if (context.request.method === "POST") return onRequestPost(context);
  return text("Method not allowed.", 405);
}
