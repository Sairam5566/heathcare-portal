# Healthcare Portal 

A full-stack web application for managing healthcare records, appointments, lab reports, and reminders for patients and doctors. The system provides a secure, role-based portal for doctors and admins to manage patient data, medical summaries, appointments, lab results, and send SMS reminders via Twilio.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Database Schema](#database-schema)
- [API Endpoints](#api-endpoints)
- [Frontend Pages](#frontend-pages)
- [Setup & Configuration](#setup--configuration)
- [How It Works](#how-it-works)
- [Security](#security)
- [License](#license)

---

## Features

- **User Authentication**: Secure login for doctors and admin with captcha and password hashing.
- **Role-based Access**: Admin can manage doctors; doctors can manage their patients.
- **Patient Management**: Add, edit, delete, and view patients, assign to doctors.
- **Medical Summaries**: Record and view detailed medical summaries for each patient.
- **Appointments**: Schedule, view, and manage appointments with conflict checking.
- **Lab Reports**: Add, edit, and view lab reports for patients.
- **Vitals & Demographics**: Record and view patient vitals and demographic information.
- **Reminders**: Send SMS reminders to patients using Twilio.
- **Dashboard**: Overview of patient data, appointments, and medical history.
- **Responsive UI**: Modern, mobile-friendly frontend using Tailwind CSS and Alpine.js/React.

---

## Architecture

- **Backend**: ASP.NET Core Minimal API (C#), Dapper ORM, SQL Server, Twilio integration.
- **Frontend**: Static HTML/CSS/JS (Tailwind, Alpine.js, some React for forms).
- **Database**: SQL Server (local, auto-bootstrapped on first run).
- **Authentication**: Custom token-based (Base64), with role distinction and captcha.

---

## Tech Stack

- **.NET 9.0** (ASP.NET Core Web)
- **Dapper** (Micro ORM for SQL)
- **Microsoft.Data.SqlClient** (SQL Server connectivity)
- **Twilio** (SMS reminders)
- **System.Drawing.Common** (Captcha image generation)
- **Tailwind CSS** (UI styling)
- **Alpine.js** and **React** (Frontend interactivity)

---

## Database Schema

The backend auto-creates and migrates the following tables:

- **Patients**: Stores patient info (name, age, gender, contact, doctor assignment, etc.)
- **Doctors**: Stores doctor info (name, specialization, username, password hash/salt)
- **Appointments**: Patient appointments (date, time, provider, notes, etc.)
- **MedicalSummaries**: Detailed visit summaries (complaints, history, vitals, doctor notes, medications, etc.)
- **Labreports**: Lab test results (test name, result, reference range, doctor, notes, etc.)



---

## API Endpoints

All endpoints are under `/api/` and require authentication (token in `Authorization` header).

### Auth
- `POST /api/login` — Login with username, password, and captcha.
- `GET /api/captcha` — Get a new captcha image.

### Doctors (Admin only)
- `GET /api/doctors` — List all doctors.
- `POST /api/doctors` — Add a new doctor.
- `DELETE /api/doctors/{id}` — Remove a doctor.

### Patients
- `GET /api/patients` — List all patients.
- `GET /api/patients/doctor/{doctorId}` — List patients for a doctor.
- `POST /api/patients` — Add a new patient.
- `GET /api/patients/{id}` — Get patient details.
- `PUT /api/patients/{id}` — Update patient.
- `DELETE /api/patients/{id}` — Delete patient.

### Medical Summaries
- `GET /api/patients/{pid}/medical-summaries` — List all summaries for a patient.
- `GET /api/patients/{pid}/medical-summaries/latest` — Get latest summary.
- `POST /api/patients/{pid}/medical-summaries` — Add new summary.
- `PUT /api/patients/{pid}/medical-summaries/{id}` — Update summary.
- `DELETE /api/patients/{pid}/medical-summaries/{id}` — Delete summary.

### Appointments
- `GET /api/patients/{pid}/appointments` — List appointments for a patient.
- `POST /api/patients/{pid}/appointments` — Add appointment.
- `DELETE /api/patients/{pid}/appointments/{id}` — Delete appointment.
- `GET /api/appointments/doctor/{doctorId}/today` — Doctor's appointments for today.

### Lab Reports
- `POST /api/labreports` — Add lab report.
- `GET /api/labreports/patient/{patientId}` — List lab reports for a patient.
- `PUT /api/labreports/{id}` — Update lab report.

### Reminders
- `POST /api/reminders/send` — Send SMS reminder via Twilio.

---

## Frontend Pages

- **login.html** — Login page with captcha.
- **admin.html** — Admin dashboard for doctor management.
- **doctor.html** — Doctor dashboard (appointments, patients, reports).
- **dashboard.html** — Patient dashboard (overview, navigation).
- **all-patients.html** — List all patients.
- **add-del-patients.html** — Add or delete patients.
- **appointment.html** — Manage appointments.
- **medical-summary.html** — View/add/edit medical summaries.
- **labs.html** — View/add/edit lab reports.
- **demographics.html** — Patient demographic info.
- **insurance.html** — Insurance details (static sample).
- **vitals.html** — Record/view patient vitals.
- **patient-remainders.html** — Manage and send reminders.
- **patient-reports.html** — Fetch lab reports by ID.

---

## Setup & Configuration

### Prerequisites

- [.NET 9.0 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/9.0)
- [SQL Server Express](https://www.microsoft.com/en-us/sql-server/sql-server-downloads) (or compatible, default: `.\SQLEXPRESS`)
- Node.js (for frontend development, optional)

### Configuration

- **Twilio**: Set your Twilio credentials in `SimpleBackend/twilio.json`:
  ```json
  {
    "Twilio": {
      "AccountSid": "YOUR_TWILIO_SID",
      "AuthToken": "YOUR_TWILIO_AUTH_TOKEN",
      "FromNumber": "+1XXXXXXXXXX"
    }
  }
  ```

- **Database**: The backend will auto-create a local database `HealthcareDb` on first run.

### Running the Project

1. **Restore dependencies**:
   ```
   dotnet restore
   ```

2. **Build and run the backend**:
   ```
   dotnet run --project SimpleBackend/SimpleBackend.csproj
   ```

3. **Access the app**:
   - Open `http://localhost:5000` (or the port shown in the console).
   - Default admin login:  
     - Username: `admin`  
     - Password: `123`

---

## How It Works

- **Authentication**: Users log in with username, password, and captcha. Admin and doctor roles are supported.
- **Doctor Management**: Admin can add or remove doctors.
- **Patient Management**: Doctors can add, edit, and view their patients.
- **Medical Summaries**: Doctors can record detailed visit notes, history, and medications.
- **Appointments**: Schedule and manage appointments, with conflict detection.
- **Lab Reports**: Add and view lab results for patients.
- **Reminders**: Send SMS reminders to patients using Twilio.
- **Frontend**: Modern, responsive UI for all major features.

---

## Security

- **Passwords**: Stored as salted SHA-256 hashes.
- **Tokens**: Custom base64 tokens for session management.
- **Captcha**: Prevents brute-force login.
- **CORS**: Enabled for all origins (can be restricted in production).
- **Role-based access**: Admin and doctor permissions enforced on backend.

---

## License

This project is for educational and demonstration purposes.  
For production use, review and enhance security, error handling, and compliance.

---

**Contributions welcome!** 
