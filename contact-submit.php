<?php
/**
 * Contact form handler for the New gTLD 2026 website.
 *
 * Configuration:
 * 1. Replace HC_SECRET with your hCaptcha secret key, or preferably
 *    define HCAPTCHA_SECRET in the server environment.
 * 2. Set CONTACT_TO to the mailbox that should receive messages.
 * 3. Ensure PHP mail() is configured on the hosting server.
 *
 * The hCaptcha site key belongs in contact.html. The secret key MUST remain
 * server-side and must never be placed in HTML or JavaScript.
 */

declare(strict_types=1);

const HCAPTCHA_VERIFY_URL = 'https://api.hcaptcha.com/siteverify';
const CONTACT_TO = 'REPLACE_WITH_YOUR_EMAIL';
const HCAPTCHA_SECRET = 'REPLACE_WITH_YOUR_HCAPTCHA_SECRET';

function fail(string $message, int $status = 400): never
{
    http_response_code($status);
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Contact — New gTLD 2026</title><style>body{font-family:system-ui,sans-serif;max-width:720px;margin:80px auto;padding:24px;color:#102033;background:#f5f8fb}.box{background:#fff;border:1px solid #dce4ec;border-radius:16px;padding:30px}a{color:#0c4fb3}</style></head><body><div class="box"><h1>Message not sent</h1><p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p><p><a href="contact.html">Return to contact form</a></p></div></body></html>';
    exit;
}

function clean_header_value(string $value): string
{
    return trim(str_replace(["\r", "\n"], '', $value));
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    fail('Invalid request method.', 405);
}

// Honeypot: legitimate users should never fill this hidden field.
$honeypot = trim((string)($_POST['website'] ?? ''));
if ($honeypot !== '') {
    fail('Spam protection rejected the submission.');
}

$name = trim((string)($_POST['name'] ?? ''));
$email = trim((string)($_POST['email'] ?? ''));
$subject = trim((string)($_POST['subject'] ?? ''));
$message = trim((string)($_POST['message'] ?? ''));
$captchaToken = trim((string)($_POST['h-captcha-response'] ?? ''));

if ($name === '' || mb_strlen($name) > 100) {
    fail('Please enter a valid name.');
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 254) {
    fail('Please enter a valid email address.');
}

if ($subject === '' || mb_strlen($subject) > 200) {
    fail('Please enter a valid subject.');
}

if ($message === '' || mb_strlen($message) > 5000) {
    fail('Please enter a message of no more than 5,000 characters.');
}

if ($captchaToken === '') {
    fail('Please complete the hCaptcha verification.');
}

$secret = getenv('HCAPTCHA_SECRET') ?: HCAPTCHA_SECRET;
$recipient = getenv('CONTACT_TO') ?: CONTACT_TO;

if ($secret === 'REPLACE_WITH_YOUR_HCAPTCHA_SECRET' || $recipient === 'REPLACE_WITH_YOUR_EMAIL') {
    fail('The contact form has not been configured by the site administrator.', 500);
}

// Verify hCaptcha server-side. The visitor IP is included when available.
$postData = [
    'secret' => $secret,
    'response' => $captchaToken,
];

if (!empty($_SERVER['REMOTE_ADDR'])) {
    $postData['remoteip'] = $_SERVER['REMOTE_ADDR'];
}

$ch = curl_init(HCAPTCHA_VERIFY_URL);
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => http_build_query($postData),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
]);

$response = curl_exec($ch);
$curlError = curl_error($ch);
$httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($response === false || $curlError !== '' || $httpCode < 200 || $httpCode >= 300) {
    fail('Spam verification could not be completed. Please try again later.', 502);
}

$captchaResult = json_decode($response, true);
if (!is_array($captchaResult) || empty($captchaResult['success'])) {
    fail('Spam verification failed. Please complete the hCaptcha challenge and try again.');
}

// Protect the mail headers from header injection.
$safeName = clean_header_value($name);
$safeEmail = clean_header_value($email);
$safeSubject = clean_header_value($subject);

$mailSubject = '[Website contact] ' . $safeSubject;
$mailBody = "New contact form submission\n\n"
    . "Name: {$safeName}\n"
    . "Email: {$safeEmail}\n"
    . "Subject: {$safeSubject}\n\n"
    . "Message:\n{$message}\n\n"
    . "Submitted: " . gmdate('Y-m-d H:i:s') . " UTC\n"
    . "IP: " . clean_header_value((string)($_SERVER['REMOTE_ADDR'] ?? 'unknown')) . "\n";

$headers = [
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'From: Website Contact <no-reply@' . preg_replace('/[^a-zA-Z0-9.-]/', '', (string)($_SERVER['HTTP_HOST'] ?? 'localhost')) . '>',
    'Reply-To: ' . $safeEmail,
];

if (!filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
    fail('The contact recipient is not configured correctly.', 500);
}

$sent = mail($recipient, $mailSubject, $mailBody, implode("\r\n", $headers));

if (!$sent) {
    fail('Your message could not be delivered. Please try again later.', 500);
}

header('Location: contact.html?sent=1', true, 303);
exit;
