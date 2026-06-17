# 🔒 SecureBook — Secure Booking System

**Course:** IKB 21503 — Secure Software Development | UniKL MIIT  
**Framework:** Django 4.2 (Python)  
**Assessment:** Mini Project — OWASP-Compliant Secure Web Application

---

## 📋 Project Description

SecureBook is a fully functional booking system built with security-first principles, implementing all OWASP Top 10 countermeasures and ASVS controls. It features user registration, login, role-based access control (Admin / Normal User), secure CRUD bookings, user profiles, and a full security audit log.

---

## ⚡ Installation Steps

### 1. Clone the repository
```bash
git clone https://github.com/Rushdrshd/Secure_Booking_Website
cd secure-booking
```

### 2. Create virtual environment
```bash
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment
```bash
cp .env.example .env
# Edit .env and set a strong SECRET_KEY
```

### 5. Run migrations
```bash
python manage.py migrate
```

### 6. Create admin superuser
```bash
python manage.py createsuperuser
# Then in Django shell, set role to admin:
python manage.py shell
>>> from booking_app.models import UserProfile
>>> from django.contrib.auth.models import User
>>> u = User.objects.get(username='your_admin_username')
>>> UserProfile.objects.filter(user=u).update(role='admin')
```

### 7. Create sample services (optional)
```bash
python manage.py shell
>>> from booking_app.models import Service
>>> from django.contrib.auth.models import User
>>> admin = User.objects.first()
>>> Service.objects.create(name="Meeting Room A", description="Large conference room", capacity=10, price=50.00, created_by=admin)
>>> Service.objects.create(name="Consultation Slot", description="1-hour consultation", capacity=1, price=80.00, created_by=admin)
```

### 8. Run the server
```bash
python manage.py runserver
```

Visit: http://127.0.0.1:8000

---

## 🔐 Security Features

| Control | Implementation |
|---|---|
| **Input Validation** | Server-side whitelisting, regex validation, ORM (no raw SQL) |
| **Authentication** | Secure login, bcrypt hashing, session timeout (30 min) |
| **Brute-Force Protection** | django-axes: 5 attempts → 1-hour lockout |
| **CSRF Protection** | Django CSRF middleware on all POST forms |
| **RBAC** | Admin / Normal User roles, enforced on every view |
| **IDOR Prevention** | UUID-based booking references (not sequential IDs) |
| **Session Security** | HttpOnly, SameSite=Lax cookies, session expiry |
| **Error Handling** | Custom 400/403/404/500 pages — no stack traces |
| **File Upload Security** | MIME-type check, extension whitelist, UUID rename, size limit |
| **Output Encoding** | Django auto-escaping in all templates (XSS prevention) |
| **Security Headers** | CSP, X-Frame-Options: DENY, X-Content-Type-Options |
| **Audit Logging** | All logins, failures, admin actions — no sensitive data logged |
| **Password Hashing** | BCryptSHA256 (OWASP ASVS V2.4) |
| **Secrets Management** | .env file, never hardcoded |

---

## 🚀 How to Run the App

```bash
# Activate virtual environment
source venv/bin/activate

# Start development server
python manage.py runserver

# Access at:
http://127.0.0.1:8000/
```

---

## 📦 Dependencies

See `requirements.txt` for full list. Key packages:

- `Django==4.2.16` — Web framework
- `django-axes==6.5.1` — Brute-force login protection
- `bcrypt==4.2.0` — Secure password hashing
- `django-csp==3.8` — Content Security Policy headers
- `Pillow==10.4.0` — Image validation for uploads
- `whitenoise==6.7.0` — Static file serving
- `python-dotenv==1.0.1` — Environment variable management
- `bleach==6.1.0` — HTML sanitization

---

## 📁 Repository Structure

```
secure-booking/
├── config/                  # Django project config
│   ├── settings.py          # All security settings
│   ├── urls.py
│   └── wsgi.py
├── booking_app/             # Main application
│   ├── models.py            # Database models (ORM)
│   ├── views.py             # Business logic + access control
│   ├── forms.py             # Input validation
│   ├── middleware.py        # Security headers (CSP)
│   ├── admin.py
│   ├── urls.py
│   └── templates/
│       └── booking_app/     # All HTML templates
├── media/uploads/           # File uploads (outside web root)
├── logs/                    # Security logs
├── requirements.txt
├── .env.example             # Environment template (no secrets)
├── .gitignore
└── README.md
```

---

## 📸 Screenshots

> Add screenshots of the running application here after setup.

---

## 👥 Team Members

| Name | Student ID | Role |
|---|---|---|
| Member 1 | ID | Development / Functionality |
| Member 2 | ID | Security Testing |
| Member 3 | ID | Mitigation & Fixes |
| Member 4 | ID | CI/CD & GitHub Management |
