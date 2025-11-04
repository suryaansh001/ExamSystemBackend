# Email Configuration Guide

## ⚠️ Current Issue: Network Unreachable on Railway

The logs show `[Errno 101] Network is unreachable` when trying to send OTP emails. This indicates:

1. **Railway environment** may have restricted outbound SMTP connections
2. **Gmail credentials** in `.env` might be incorrect
3. **Network firewall** blocking port 587 (TLS SMTP)

---

## ✅ Solution 1: Verify & Fix Gmail Configuration

### Step 1: Use Gmail App Password (NOT regular password)

Gmail requires **App Passwords** for third-party applications:

1. Go to: https://myaccount.google.com/apppasswords
2. Select: **Mail** and **Windows Computer** (or your device)
3. Generate a new 16-character password
4. Copy the password (spaces will be removed automatically)

### Step 2: Update `.env` file

```properties
GMAIL_USER='sharmadev0042@gmail.com'
GMAIL_PASS='ezzh hnnd uvxq ciqf'
SMTP_SERVER='smtp.gmail.com'
SMTP_PORT='587'
```

**⚠️ Important:**
- `GMAIL_PASS` must be an **App Password**, not your Gmail account password
- Spaces in the password are fine - they'll be used as-is
- Keep `.env` file **secure** and **never commit** to git

### Step 3: Test Email Configuration

Run this health check:

```bash
curl https://your-railway-domain.com/health/email
```

Expected response:
```json
{
  "status": "healthy",
  "email": "sharmadev0042@gmail.com",
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "message": "Email configuration verified"
}
```

---

## ❌ Solution 2: Fallback Mode (Console Only)

If Gmail SMTP is unavailable (network restrictions on Railway), the system will automatically:

1. **Print OTP to console logs** (visible in Railway dashboard)
2. **Show message to user**: "OTP shown in console"
3. **Continue working** without actual email sending

This is **fine for testing** but not suitable for production.

### How to test in console mode:

1. User requests OTP at `/send-otp`
2. Check Railway logs for: `OTP for {email}: 123456`
3. Use this OTP to complete verification

---

## 🔧 Checking Email Status

### View Current Configuration

```bash
# Health check endpoint
GET /health

# Email-specific check
GET /health/email
```

### Check Railway Logs

Look for these messages:

**Success:**
```
✓ Email sent successfully to user@example.com
```

**Network Issue:**
```
❌ Network error: [Errno 101] Network is unreachable
Note: Cannot reach Gmail SMTP server
```

**Authentication Issue:**
```
❌ Gmail authentication failed: [Errno 535] 5.7.8 Username and password not accepted
```

---

## 🚀 Production Deployment Checklist

- [ ] Gmail App Password generated and stored
- [ ] `.env` file has valid `GMAIL_USER` and `GMAIL_PASS`
- [ ] `/health/email` endpoint returns `"status": "healthy"`
- [ ] Test OTP received at registered email
- [ ] Verify OTP successfully completes login
- [ ] Check Railway logs for any email errors

---

## 📋 Common Issues & Solutions

### Issue 1: "Gmail authentication failed"
**Cause:** Using regular Gmail password instead of App Password
**Fix:** Use 16-character App Password from https://myaccount.google.com/apppasswords

### Issue 2: "Network is unreachable"
**Cause:** Railway environment blocking outbound SMTP (port 587)
**Solution:** 
- Contact Railway support about SMTP access
- Or configure alternative email service (SendGrid, Mailgun)
- Or use console-only mode for testing

### Issue 3: "OTP for {email}: ..." printed but not sent
**Expected:** This is normal during testing. OTP appears in logs and console output.
**To send emails:** Ensure GMAIL_USER and GMAIL_PASS are set correctly in `.env`

### Issue 4: "Connection timeout"
**Cause:** SMTP server (smtp.gmail.com) not reachable
**Fix:**
- Verify `SMTP_SERVER` and `SMTP_PORT` are correct
- Check network connectivity
- Try from local machine first to isolate the issue

---

## 🔐 Security Best Practices

✅ **DO:**
- Use Gmail **App Passwords** (16 characters)
- Keep `.env` file **secret** (never commit)
- Enable 2-Factor Authentication on Gmail account
- Rotate app passwords periodically

❌ **DON'T:**
- Use actual Gmail account password in code
- Commit `.env` file to repository
- Share app passwords publicly
- Use same password for multiple services

---

## 📞 Support

If email still doesn't work after following this guide:

1. Check `/health/email` endpoint for detailed error
2. Review Railway logs for SMTP errors
3. Verify Gmail settings at https://myaccount.google.com/security
4. Test locally with same credentials
5. Consider alternative email provider if Railway blocks SMTP

---

## 🌐 Alternative Email Providers

If Railway blocks Gmail SMTP, consider:

### SendGrid (Recommended)
- No SMTP port restrictions usually
- Free tier available
- Better for transactional emails

### Mailgun
- Good uptime and reliability
- Easy API integration

### AWS SES
- Scalable for high volume
- Good for production

Update `main.py` to support these if needed.
