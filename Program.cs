using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using Microsoft.Data.SqlClient;
using Dapper;
using System.Linq;
using System;
using System.Text.Json;
using System.Net.Http;
using System.Net.Http.Json;
using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using System.Collections.Concurrent;
using System.Drawing;
using System.Drawing.Imaging;
using Microsoft.AspNetCore.Mvc;
using DotNetEnv;

var builder = WebApplication.CreateBuilder(args);

// Add CORS policy
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// Load environment variables from .env
Env.Load();

// Register Twilio options for DI using environment variables
builder.Services.Configure<TwilioOptions>(options => {
    options.AccountSid = Environment.GetEnvironmentVariable("TWILIO_ACCOUNT_SID") ?? string.Empty;
    options.AuthToken = Environment.GetEnvironmentVariable("TWILIO_AUTH_TOKEN") ?? string.Empty;
    options.FromNumber = Environment.GetEnvironmentVariable("TWILIO_FROM_NUMBER") ?? string.Empty;
});

// camelCase JSON for JS
builder.Services.ConfigureHttpJsonOptions(opt =>
    opt.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase);

var app = builder.Build();

// Use CORS
app.UseCors();

// ------------ SQL Server bootstrap -------------
const string DbName = "HealthcareDb";
const string ServerName = @".\SQLEXPRESS";

var masterConn = $"Server={ServerName};Database=master;Trusted_Connection=True;Encrypt=False;TrustServerCertificate=True;";
var cs = $"Server={ServerName};Database={DbName};Trusted_Connection=True;Encrypt=False;TrustServerCertificate=True;";

using (var master = new SqlConnection(masterConn))
    master.Execute($"IF DB_ID('{DbName}') IS NULL CREATE DATABASE {DbName};");

using (var init = new SqlConnection(cs))
    init.Execute(@"
        IF OBJECT_ID('dbo.Patients', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.Patients (
                Id      INT IDENTITY(1,1) PRIMARY KEY,
                Name    NVARCHAR(100) NOT NULL,
                Age     INT NULL,
                Gender  NVARCHAR(20) NULL,
                Contact NVARCHAR(50) NULL,
                Note    NVARCHAR(200) NULL,
                DoctorId INT NULL,
                Specialization NVARCHAR(100) NULL
            );
        END
        IF OBJECT_ID('dbo.Appointments', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.Appointments (
                Id           INT IDENTITY(1,1) PRIMARY KEY,
                PatientId    INT NOT NULL,
                Date         DATE NOT NULL,
                Time         NVARCHAR(10) NULL,
                Provider     NVARCHAR(100) NOT NULL,
                Reason       NVARCHAR(200) NULL,
                DoctorNotes  NVARCHAR(500) NULL,
                Remedy       NVARCHAR(200) NULL,
                FOREIGN KEY (PatientId) REFERENCES dbo.Patients(Id) ON DELETE CASCADE
            );
        END;

        IF OBJECT_ID('dbo.MedicalSummaries', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.MedicalSummaries (
                Id                  INT IDENTITY(1,1) PRIMARY KEY,
                PatientId           INT NOT NULL,
                VisitDate           DATETIME NOT NULL DEFAULT GETDATE(),
                ChiefComplaint      NVARCHAR(MAX),
                HistoryOfPresentIllness NVARCHAR(MAX),
                PastMedicalHistory  NVARCHAR(MAX),
                FamilyHistory       NVARCHAR(MAX),
                SocialHistory       NVARCHAR(MAX),
                Allergies           NVARCHAR(MAX),
                VitalSigns          NVARCHAR(MAX),
                DoctorName          NVARCHAR(100) NULL,
                Specialization      NVARCHAR(100) NULL,
                VisitTime           NVARCHAR(20) NULL,
                DoctorNotes         NVARCHAR(MAX) NULL,
                Medications         NVARCHAR(MAX) NULL, -- Will store JSON array of medications
                NextVisitDate       DATE NULL,
                SpecialInstructions NVARCHAR(MAX) NULL,
                FOREIGN KEY (PatientId) REFERENCES dbo.Patients(Id) ON DELETE CASCADE
            );
        END
        ELSE
        BEGIN
            -- Add new columns if they don't exist
            IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('dbo.MedicalSummaries') AND name = 'DoctorName')
            BEGIN
                EXEC('ALTER TABLE dbo.MedicalSummaries ADD DoctorName NVARCHAR(100) NULL');
                EXEC('ALTER TABLE dbo.MedicalSummaries ADD Specialization NVARCHAR(100) NULL');
                EXEC('ALTER TABLE dbo.MedicalSummaries ADD VisitTime NVARCHAR(20) NULL');
                EXEC('ALTER TABLE dbo.MedicalSummaries ADD DoctorNotes NVARCHAR(MAX) NULL');
                EXEC('ALTER TABLE dbo.MedicalSummaries ADD Medications NVARCHAR(MAX) NULL');
                EXEC('ALTER TABLE dbo.MedicalSummaries ADD NextVisitDate DATE NULL');
                EXEC('ALTER TABLE dbo.MedicalSummaries ADD SpecialInstructions NVARCHAR(MAX) NULL');
            END
        END");

// ------------ Doctor & Admin Table Bootstrap -------------

// Add Doctors table if not exists
using (var init = new SqlConnection(cs))
    init.Execute(@"
        IF OBJECT_ID('dbo.Doctors', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.Doctors (
                Id INT IDENTITY(1,1) PRIMARY KEY,
                Name NVARCHAR(100) NOT NULL,
                Specialization NVARCHAR(100) NOT NULL,
                Username NVARCHAR(50) NOT NULL UNIQUE,
                Password NVARCHAR(100) NOT NULL
            );
        END
    ");

// Add DoctorId and Specialization to Patients if not exists
using (var alter = new SqlConnection(cs))
    alter.Execute(@"
        IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('dbo.Patients') AND name = 'DoctorId')
            ALTER TABLE dbo.Patients ADD DoctorId INT NULL;
        IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('dbo.Patients') AND name = 'Specialization')
            ALTER TABLE dbo.Patients ADD Specialization NVARCHAR(100) NULL;
    ");

// Robust migration for Doctors table
try {
    using (var alter = new SqlConnection(cs))
        alter.Execute(@"
            IF COL_LENGTH('Doctors', 'PasswordHash') IS NULL
                ALTER TABLE Doctors ADD PasswordHash NVARCHAR(256) NULL;
            IF COL_LENGTH('Doctors', 'PasswordSalt') IS NULL
                ALTER TABLE Doctors ADD PasswordSalt NVARCHAR(128) NULL;
            IF COL_LENGTH('Doctors', 'Password') IS NOT NULL
                ALTER TABLE Doctors DROP COLUMN Password;
        ");
} catch (Exception ex) {
    Console.WriteLine($"[MIGRATION ERROR] {ex.Message}");
}

// ------------ Auth Helpers -------------
string GenerateToken(string username, string role)
{
    // Simple token: base64(username:role:timestamp)
    var raw = $"{username}:{role}:{DateTime.UtcNow.Ticks}";
    return Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
}

string GenerateSalt(int size = 16)
{
    var rng = new RNGCryptoServiceProvider();
    var buff = new byte[size];
    rng.GetBytes(buff);
    return Convert.ToBase64String(buff);
}

string HashPassword(string password, string salt)
{
    using var sha = SHA256.Create();
    var combined = Encoding.UTF8.GetBytes(password + salt);
    var hash = sha.ComputeHash(combined);
    return Convert.ToBase64String(hash);
}

bool VerifyPassword(string password, string salt, string hash)
{
    var computed = HashPassword(password, salt);
    return computed == hash;
}

(bool valid, string username, string role) ValidateToken(string? token)
{
    if (string.IsNullOrEmpty(token)) return (false, "", "");
    try {
        var raw = Encoding.UTF8.GetString(Convert.FromBase64String(token));
        var parts = raw.Split(':');
        if (parts.Length < 3) return (false, "", "");
        return (true, parts[0], parts[1]);
    } catch { return (false, "", ""); }
}

// ------------ Captcha System -------------
var captchaStore = new ConcurrentDictionary<string, (string code, DateTime expires)>();
var captchaRng = new Random();

string GenerateCaptchaCode(int length = 6)
{
    const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    return new string(Enumerable.Repeat(chars, length).Select(s => s[captchaRng.Next(s.Length)]).ToArray());
}

string GenerateCaptchaImage(string code)
{
    int width = 160, height = 40;
    using var bmp = new Bitmap(width, height);
    using var gfx = Graphics.FromImage(bmp);
    gfx.Clear(Color.White);
    using var font = new Font("Arial", 22, FontStyle.Bold);
    using var brush = new SolidBrush(Color.FromArgb(60, 40, 20));
    // Center the text horizontally
    var textSize = gfx.MeasureString(code, font);
    float x = (width - textSize.Width) / 2;
    float y = (height - textSize.Height) / 2;
    gfx.DrawString(code, font, brush, x, y);
    // Add some noise
    for (int i = 0; i < 10; i++)
        gfx.DrawEllipse(Pens.LightGray, captchaRng.Next(width), captchaRng.Next(height), 5, 5);
    using var ms = new System.IO.MemoryStream();
    bmp.Save(ms, ImageFormat.Png);
    return "data:image/png;base64," + Convert.ToBase64String(ms.ToArray());
}

// GET /api/captcha: returns { id, image }
app.MapGet("/api/captcha", () => {
    var code = GenerateCaptchaCode();
    var id = Guid.NewGuid().ToString();
    captchaStore[id] = (code, DateTime.UtcNow.AddMinutes(5));
    var image = GenerateCaptchaImage(code);
    return Results.Ok(new { id, image });
});

// Helper: Validate captcha (now case sensitive)
bool ValidateCaptcha(string id, string userInput)
{
    if (!captchaStore.TryGetValue(id, out var entry)) return false;
    if (entry.expires < DateTime.UtcNow) { captchaStore.TryRemove(id, out _); return false; }
    var valid = string.Equals(entry.code, userInput, StringComparison.Ordinal); // Case sensitive
    if (valid) captchaStore.TryRemove(id, out _); // One-time use
    return valid;
}

// ------------ Auth Endpoints -------------
app.MapPost("/api/login", async (HttpRequest req) => {
    var data = await System.Text.Json.JsonSerializer.DeserializeAsync<LoginRequest>(req.Body, new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    Console.WriteLine($"[LOGIN] Request: {{ Username: {data?.Username}, Password: {data?.Password}, CaptchaId: {data?.CaptchaId}, Captcha: {data?.Captcha} }}");
    if (data == null) return Results.BadRequest();
    if (string.IsNullOrWhiteSpace(data.CaptchaId) || string.IsNullOrWhiteSpace(data.Captcha) || !captchaStore.TryGetValue(data.CaptchaId, out var entry) || entry.expires < DateTime.UtcNow) {
        return Results.BadRequest(new { error = "Captcha is incorrect" });
    }
    if (!ValidateCaptcha(data.CaptchaId, data.Captcha)) {
        return Results.BadRequest(new { error = "Captcha is incorrect" });
    }
    if (data.Username == "admin" && data.Password == "123") {
        var token = GenerateToken("admin", "admin");
        Console.WriteLine($"[LOGIN] Admin token: {token}");
        return Results.Ok(new { token, role = "admin" });
    }
    using var db = new SqlConnection(cs);
    var doctor = await db.QuerySingleOrDefaultAsync<Doctor>("SELECT * FROM Doctors WHERE Username = @Username", new { data.Username });
    if (doctor == null) {
        Console.WriteLine("[LOGIN] Doctor not found");
        return Results.BadRequest(new { error = "Invalid username or password" });
    }
    if (!VerifyPassword(data.Password, doctor.PasswordSalt, doctor.PasswordHash)) {
        Console.WriteLine("[LOGIN] Wrong password for doctor: " + doctor.Username);
        return Results.BadRequest(new { error = "Invalid username or password" });
    }
    var docToken = GenerateToken(doctor.Username, "doctor");
    Console.WriteLine($"[LOGIN] Doctor token: {docToken}, id: {doctor.Id}, name: {doctor.Name}, specialization: {doctor.Specialization}");
    return Results.Ok(new { token = docToken, role = "doctor", doctorId = doctor.Id, name = doctor.Name, specialization = doctor.Specialization });
});

// ------------ Doctor Management (Admin only) -------------
app.MapGet("/api/doctors", async (HttpRequest req) => {
    var token = req.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var (valid, username, role) = ValidateToken(token);
    if (!valid || (role != "admin" && role != "doctor")) return Results.Unauthorized();
    using var db = new SqlConnection(cs);
    var doctors = (await db.QueryAsync<Doctor>("SELECT * FROM Doctors")).ToList();
    var result = doctors.Select(d => new { id = d.Id, name = d.Name, specialization = d.Specialization, username = d.Username }).ToList();
    return Results.Ok(result);
});

app.MapPost("/api/doctors", async (HttpRequest req) => {
    try {
        var token = req.Headers["Authorization"].ToString().Replace("Bearer ", "");
        var (valid, username, role) = ValidateToken(token);
        if (!valid || role != "admin") return Results.Unauthorized();
        var doc = await req.ReadFromJsonAsync<DoctorInput>();
        if (doc == null) {
            Console.WriteLine("[ADD DOCTOR] Invalid input");
            return Results.BadRequest();
        }
        var salt = GenerateSalt();
        var hash = HashPassword(doc.Password, salt);
        using var db = new SqlConnection(cs);
        var id = await db.ExecuteScalarAsync<int>(
            "INSERT INTO Doctors (Name, Specialization, Username, PasswordHash, PasswordSalt) VALUES (@Name, @Specialization, @Username, @PasswordHash, @PasswordSalt); SELECT SCOPE_IDENTITY();",
            new { doc.Name, doc.Specialization, doc.Username, PasswordHash = hash, PasswordSalt = salt }
        );
        Console.WriteLine($"[ADD DOCTOR] Success: {doc.Username}");
        return Results.Created($"/api/doctors/{id}", new { id });
    } catch (Exception ex) {
        Console.WriteLine($"[ADD DOCTOR ERROR] {ex}");
        return Results.Problem("Internal server error: " + ex.Message, statusCode: 500);
    }
});

app.MapDelete("/api/doctors/{id:int}", async (int id, HttpRequest req) => {
    var token = req.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var (valid, username, role) = ValidateToken(token);
    if (!valid || role != "admin") return Results.Unauthorized();
    using var db = new SqlConnection(cs);
    var rows = await db.ExecuteAsync("DELETE FROM Doctors WHERE Id = @id", new { id });
    return rows == 0 ? Results.NotFound() : Results.NoContent();
});

// ------------ Patient Endpoints (with Doctor assignment) -------------
app.MapGet("/api/patients", async (HttpRequest req) => {
    var token = req.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var (valid, username, role) = ValidateToken(token);
    if (!valid) return Results.Unauthorized();
    using var db = new SqlConnection(cs);
    var pts = await db.QueryAsync<Patient>("SELECT * FROM dbo.Patients ORDER BY Id DESC");
    return Results.Ok(pts);
});

app.MapGet("/api/patients/doctor/{doctorId:int}", async (int doctorId, HttpRequest req) => {
    var token = req.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var (valid, username, role) = ValidateToken(token);
    if (!valid) return Results.Unauthorized();
    using var db = new SqlConnection(cs);
    var pts = await db.QueryAsync<Patient>("SELECT * FROM dbo.Patients WHERE DoctorId = @doctorId ORDER BY Id DESC", new { doctorId });
    return Results.Ok(pts);
});

// ------------ Patient Visit Count endpoints -------------
app.MapGet("/api/patients/doctor/{doctorId:int}/count", async (int doctorId, string period, HttpRequest req) => {
    var token = req.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var (valid, username, role) = ValidateToken(token);
    if (!valid) return Results.Unauthorized();

    using var db = new SqlConnection(cs);

    var today = DateTime.Today;
    string dateFilter;
    DateTime weekStart = today.AddDays(-(int)today.DayOfWeek + (int)DayOfWeek.Monday);
    if (weekStart > today) weekStart = weekStart.AddDays(-7);
    DateTime weekEnd = weekStart.AddDays(7);

    var parameters = new {
        doctorId,
        today = today, // DateTime.Today is midnight
        weekStart,
        weekEnd,
        monthStart = new DateTime(today.Year, today.Month, 1),
        monthEnd = new DateTime(today.Year, today.Month, 1).AddMonths(1),
        yearStart = new DateTime(today.Year, 1, 1),
        yearEnd = new DateTime(today.Year + 1, 1, 1)
    };

    switch (period.ToLower())
    {
        case "today":
            dateFilter = "CAST(ms.VisitDate AS DATE) = CAST(@today AS DATE)";
            break;
        case "week":
            dateFilter = "ms.VisitDate >= @weekStart AND ms.VisitDate < @weekEnd";
            break;
        case "month":
            dateFilter = "ms.VisitDate >= @monthStart AND ms.VisitDate < @monthEnd";
            break;
        case "year":
            dateFilter = "ms.VisitDate >= @yearStart AND ms.VisitDate < @yearEnd";
            break;
        default:
            return Results.BadRequest("Invalid period. Use: today, week, month, or year");
    }

    var query = $@"
        SELECT COUNT(*) as VisitCount
        FROM dbo.MedicalSummaries ms
        INNER JOIN dbo.Patients p ON ms.PatientId = p.Id
        WHERE p.DoctorId = @doctorId 
        AND {dateFilter}";

    var count = await db.QuerySingleOrDefaultAsync<int>(query, parameters);

    // Debug: log the query and parameters if count is 0
    if (count == 0)
    {
        Console.WriteLine($"[DEBUG] Query: {query}");
        Console.WriteLine($"[DEBUG] Params: doctorId={doctorId}, today={today:yyyy-MM-dd}, weekStart={weekStart:yyyy-MM-dd}, weekEnd={weekEnd:yyyy-MM-dd}, monthStart={parameters.monthStart:yyyy-MM-dd}, monthEnd={parameters.monthEnd:yyyy-MM-dd}, yearStart={parameters.yearStart:yyyy-MM-dd}, yearEnd={parameters.yearEnd:yyyy-MM-dd}");
    }

    return Results.Ok(count);
});

app.MapPost("/api/patients", async (HttpRequest req) => {
    var token = req.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var (valid, username, role) = ValidateToken(token);
    if (!valid) return Results.Unauthorized();
    var input = await req.ReadFromJsonAsync<PatientInput>();
    if (input == null) return Results.BadRequest();
    using var db = new SqlConnection(cs);
    var id = await db.ExecuteScalarAsync<int>(
        @"INSERT INTO dbo.Patients (Name, Age, Gender, Contact, Note, DoctorId, Specialization) 
          VALUES (@Name, @Age, @Gender, @Contact, @Note, @DoctorId, @Specialization); 
          SELECT SCOPE_IDENTITY();", 
        input);
    return Results.Created($"/api/patients/{id}", new { id });
});

app.MapGet("/api/patients/{id:int}", async (int id) =>
{
    using var db = new SqlConnection(cs);
    var p = await db.QuerySingleOrDefaultAsync<Patient>("SELECT * FROM dbo.Patients WHERE Id = @id", new { id });
    return p is null ? Results.NotFound() : Results.Ok(p);
});

app.MapPut("/api/patients/{id:int}", async (int id, PatientInput input) =>
{
    using var db = new SqlConnection(cs);
    var rows = await db.ExecuteAsync(
        @"UPDATE dbo.Patients 
          SET Name=@Name, Age=@Age, Gender=@Gender, Contact=@Contact, Note=@Note 
          WHERE Id=@id", 
        new { id, input.Name, input.Age, input.Gender, input.Contact, input.Note });
    return rows == 0 ? Results.NotFound() : Results.NoContent();
});

app.MapDelete("/api/patients/{id:int}", async (int id) =>
{
    using var db = new SqlConnection(cs);
    var rows = await db.ExecuteAsync("DELETE FROM dbo.Patients WHERE Id = @id", new { id });
    return rows == 0 ? Results.NotFound() : Results.NoContent();
});

// ------------ Medical Summary endpoints -------------
app.MapGet("/api/patients/{pid:int}/medical-summaries", async (int pid) =>
{
    using var db = new SqlConnection(cs);
    var summaries = await db.QueryAsync<dynamic>(
        @"SELECT *, 
                CASE WHEN Medications IS NOT NULL THEN TRY_CAST(Medications AS NVARCHAR(MAX)) ELSE NULL END AS MedicationsJson
         FROM dbo.MedicalSummaries 
         WHERE PatientId = @pid 
         ORDER BY VisitDate DESC",
        new { pid });

    var result = summaries.Select(s => new 
    {
        s.Id,
        s.PatientId,
        s.VisitDate,
        s.ChiefComplaint,
        s.HistoryOfPresentIllness,
        s.PastMedicalHistory,
        s.FamilyHistory,
        s.SocialHistory,
        s.Allergies,
        s.VitalSigns,
        s.DoctorName,
        s.Specialization,
        s.VisitTime,
        s.DoctorNotes,
        Medications = !string.IsNullOrEmpty(s.MedicationsJson) 
            ? JsonSerializer.Deserialize<List<Medication>>(s.MedicationsJson) 
            : new List<Medication>(),
        s.NextVisitDate,
        s.SpecialInstructions
    });
    return Results.Ok(result);
});

app.MapGet("/api/patients/{pid:int}/medical-summaries/latest", async (int pid) =>
{
    using var db = new SqlConnection(cs);
    var summary = await db.QueryFirstOrDefaultAsync<dynamic>(
        @"SELECT TOP 1 *, 
                 CASE WHEN Medications IS NOT NULL THEN TRY_CAST(Medications AS NVARCHAR(MAX)) ELSE NULL END AS MedicationsJson
          FROM dbo.MedicalSummaries 
          WHERE PatientId = @pid 
          ORDER BY VisitDate DESC",
        new { pid });
    
    if (summary == null) return Results.NotFound();
    
    var result = new 
    {
        summary.Id,
        summary.PatientId,
        summary.VisitDate,
        summary.ChiefComplaint,
        summary.HistoryOfPresentIllness,
        summary.PastMedicalHistory,
        summary.FamilyHistory,
        summary.SocialHistory,
        summary.Allergies,
        summary.VitalSigns,
        summary.DoctorName,
        summary.Specialization,
        summary.VisitTime,
        summary.DoctorNotes,
        Medications = !string.IsNullOrEmpty(summary.MedicationsJson) 
            ? JsonSerializer.Deserialize<List<Medication>>(summary.MedicationsJson) 
            : new List<Medication>(),
        summary.NextVisitDate,
        summary.SpecialInstructions
    };
    
    return Results.Ok(result);
});

app.MapPost("/api/patients/{pid:int}/medical-summaries", async (int pid, MedicalSummaryInput input) =>
{
    using var db = new SqlConnection(cs);
    var id = await db.ExecuteScalarAsync<int>(
        @"INSERT INTO dbo.MedicalSummaries 
          (PatientId, VisitDate, ChiefComplaint, HistoryOfPresentIllness, PastMedicalHistory, 
           FamilyHistory, SocialHistory, Allergies, VitalSigns, DoctorName, Specialization, 
           VisitTime, DoctorNotes, Medications, NextVisitDate, SpecialInstructions) 
          VALUES (@PatientId, @VisitDate, @ChiefComplaint, @HistoryOfPresentIllness, @PastMedicalHistory, 
                  @FamilyHistory, @SocialHistory, @Allergies, @VitalSigns, @DoctorName, @Specialization, 
                  @VisitTime, @DoctorNotes, @Medications, @NextVisitDate, @SpecialInstructions); 
          SELECT SCOPE_IDENTITY();",
        new 
        { 
            PatientId = pid, 
            VisitDate = input.VisitDate,
            ChiefComplaint = input.ChiefComplaint ?? string.Empty, 
            HistoryOfPresentIllness = input.HistoryOfPresentIllness ?? string.Empty,
            PastMedicalHistory = input.PastMedicalHistory ?? string.Empty,
            FamilyHistory = input.FamilyHistory ?? string.Empty,
            SocialHistory = input.SocialHistory ?? string.Empty,
            Allergies = input.Allergies ?? string.Empty,
            VitalSigns = input.VitalSigns ?? string.Empty,
            DoctorName = input.DoctorName ?? string.Empty,
            Specialization = input.Specialization ?? string.Empty,
            VisitTime = input.VisitTime ?? string.Empty,
            DoctorNotes = input.DoctorNotes ?? string.Empty,
            Medications = input.Medications != null ? JsonSerializer.Serialize(input.Medications) : string.Empty,
            NextVisitDate = input.NextVisitDate ?? string.Empty,
            SpecialInstructions = input.SpecialInstructions ?? string.Empty
        });
    
    return Results.Created($"/api/patients/{pid}/medical-summaries/{id}", new { id });
});

// POST endpoint for deleting medical summaries (for clients that don't support DELETE)
app.MapPost("/api/patients/{pid:int}/medical-summaries/{id:int}/delete", async (int pid, int id) =>
{
    using var db = new SqlConnection(cs);
    var rowsAffected = await db.ExecuteAsync(
        "DELETE FROM dbo.MedicalSummaries WHERE Id = @id AND PatientId = @pid",
        new { pid, id });
    
    return rowsAffected > 0 ? Results.Ok() : Results.NotFound();
});

// DELETE endpoint for medical summaries
app.MapDelete("/api/patients/{pid:int}/medical-summaries/{id:int}", async (int pid, int id) =>
{
    using var db = new SqlConnection(cs);
    var rowsAffected = await db.ExecuteAsync(
        "DELETE FROM dbo.MedicalSummaries WHERE Id = @id AND PatientId = @pid",
        new { pid, id });
    
    return rowsAffected > 0 ? Results.Ok() : Results.NotFound();
});

app.MapPut("/api/patients/{pid:int}/medical-summaries/{id:int}", async (int pid, int id, MedicalSummaryInput input) =>
{
    using var db = new SqlConnection(cs);
    
    // Convert medications list to JSON string
    var medicationsJson = input.Medications != null 
        ? JsonSerializer.Serialize(input.Medications) 
        : null;

    var rowsAffected = await db.ExecuteAsync(
        @"UPDATE dbo.MedicalSummaries 
          SET VisitDate = @VisitDate,
              ChiefComplaint = @ChiefComplaint,
              DoctorName = @DoctorName,
              Specialization = @Specialization,
              VisitTime = @VisitTime,
              DoctorNotes = @DoctorNotes,
              Medications = @Medications,
              NextVisitDate = @NextVisitDate,
              SpecialInstructions = @SpecialInstructions
          WHERE Id = @Id AND PatientId = @PatientId",
        new 
        {
            Id = id,
            PatientId = pid,
            input.VisitDate,
            input.ChiefComplaint,
            input.DoctorName,
            input.Specialization,
            input.VisitTime,
            input.DoctorNotes,
            Medications = medicationsJson,
            input.NextVisitDate,
            input.SpecialInstructions
        });
    
    return rowsAffected > 0 ? Results.Ok() : Results.NotFound();
});

app.MapGet("/api/patients/{pid:int}/medical-summaries/{id:int}", async (int pid, int id) =>
{
    using var db = new SqlConnection(cs);
    var summary = await db.QueryFirstOrDefaultAsync(
        @"SELECT *, 
                 CASE WHEN Medications IS NOT NULL THEN TRY_CAST(Medications AS NVARCHAR(MAX)) ELSE NULL END AS MedicationsJson
          FROM dbo.MedicalSummaries 
          WHERE PatientId = @pid AND Id = @id",
        new { pid, id });
    if (summary == null) return Results.NotFound();

    var result = new
    {
        summary.Id,
        summary.PatientId,
        summary.VisitDate,
        summary.ChiefComplaint,
        summary.HistoryOfPresentIllness,
        summary.PastMedicalHistory,
        summary.FamilyHistory,
        summary.SocialHistory,
        summary.Allergies,
        summary.VitalSigns,
        summary.DoctorName,
        summary.Specialization,
        summary.VisitTime,
        summary.DoctorNotes,
        Medications = !string.IsNullOrEmpty(summary.MedicationsJson)
            ? JsonSerializer.Deserialize<List<Medication>>(summary.MedicationsJson)
            : new List<Medication>(),
        summary.NextVisitDate,
        summary.SpecialInstructions
    };
    return Results.Ok(result);
});

// ------------ Labreports endpoints -------------

app.MapPost("/api/labreports", async (HttpRequest req) => {
    var token = req.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var (valid, username, role) = ValidateToken(token);
    if (!valid) return Results.Unauthorized();
    var input = await req.ReadFromJsonAsync<LabReportInput>();
    if (input == null) return Results.BadRequest();
    using var db = new SqlConnection(cs);
    try {
        var id = await db.ExecuteScalarAsync<int>(
            @"INSERT INTO dbo.Labreports (
                PatientID, ReportDate, TestName, TestResult, ReferenceRange, Units, DoctorID, Notes,
                PhysiologicBasis, Interpretation, Comments, PhoneNumber, CreatedAt, UpdatedAt, DateOfVisit)
              VALUES (
                @PatientID, @ReportDate, @TestName, @TestResult, @ReferenceRange, @Units, @DoctorID, @Notes,
                @PhysiologicBasis, @Interpretation, @Comments, @PhoneNumber, @CreatedAt, @UpdatedAt, @DateOfVisit);
              SELECT SCOPE_IDENTITY();",
            new {
                input.PatientID,
                input.ReportDate,
                input.TestName,
                input.TestResult,
                input.ReferenceRange,
                input.Units,
                input.DoctorID,
                input.Notes,
                PhysiologicBasis = input.PhysiologicBasis ?? (object)DBNull.Value,
                Interpretation = input.Interpretation ?? (object)DBNull.Value,
                Comments = input.Comments ?? (object)DBNull.Value,
                PhoneNumber = input.PhoneNumber ?? (object)DBNull.Value,
                input.CreatedAt,
                input.UpdatedAt,
                DateOfVisit = input.DateOfVisit ?? (object)DBNull.Value
            });
        var saved = await db.QuerySingleOrDefaultAsync<LabReport>(
            "SELECT LabReportID, PatientID, ReportDate, TestName, TestResult, ReferenceRange, Units, DoctorID, Notes, PhysiologicBasis, Interpretation, Comments, PhoneNumber, CreatedAt, UpdatedAt, DateOfVisit FROM dbo.Labreports WHERE LabReportID = @id",
            new { id });
        return Results.Ok(saved);
    } catch (Exception ex) {
        Console.WriteLine($"[LABREPORTS][ERROR] {ex.Message}\n{ex.StackTrace}");
        return Results.Problem("Failed to save lab report: " + ex.Message, statusCode: 500);
    }
});

app.MapGet("/api/labreports/{id:int}", async (int id, int patientId, HttpRequest req) => {
    var token = req.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var (valid, username, role) = ValidateToken(token);
    if (!valid) return Results.Unauthorized();
    using var db = new SqlConnection(cs);
    var report = await db.QuerySingleOrDefaultAsync<LabReport>(
        "SELECT * FROM dbo.Labreports WHERE LabReportID = @id AND PatientID = @patientId",
        new { id, patientId });
    return report == null ? Results.NotFound() : Results.Ok(report);
});

app.MapGet("/api/labreports/patient/{patientId:int}", async (int patientId, int doctorId, HttpRequest req) => {
    var token = req.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var (valid, username, role) = ValidateToken(token);
    if (!valid) return Results.Unauthorized();
    using var db = new SqlConnection(cs);
    var reports = await db.QueryAsync<LabReport>(
        "SELECT * FROM dbo.Labreports WHERE PatientID = @patientId AND DoctorID = @doctorId ORDER BY ReportDate DESC",
        new { patientId, doctorId });
    return Results.Ok(reports);
});

app.MapPut("/api/labreports/{id:int}", async (int id, HttpRequest req) => {
    var token = req.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var (valid, username, role) = ValidateToken(token);
    if (!valid) return Results.Unauthorized();
    var input = await req.ReadFromJsonAsync<LabReportInput>();
    if (input == null) return Results.BadRequest();
    using var db = new SqlConnection(cs);
    try {
        var rows = await db.ExecuteAsync(
            @"UPDATE dbo.Labreports SET
                PatientID = @PatientID,
                ReportDate = @ReportDate,
                TestName = @TestName,
                TestResult = @TestResult,
                ReferenceRange = @ReferenceRange,
                Units = @Units,
                DoctorID = @DoctorID,
                Notes = @Notes,
                PhysiologicBasis = @PhysiologicBasis,
                Interpretation = @Interpretation,
                Comments = @Comments,
                PhoneNumber = @PhoneNumber,
                CreatedAt = @CreatedAt,
                UpdatedAt = @UpdatedAt,
                DateOfVisit = @DateOfVisit
              WHERE LabReportID = @id",
            new {
                id,
                input.PatientID,
                input.ReportDate,
                input.TestName,
                input.TestResult,
                input.ReferenceRange,
                input.Units,
                input.DoctorID,
                input.Notes,
                input.PhysiologicBasis,
                input.Interpretation,
                input.Comments,
                input.PhoneNumber,
                input.CreatedAt,
                input.UpdatedAt,
                DateOfVisit = input.DateOfVisit ?? (object)DBNull.Value
            });
        return rows > 0 ? Results.Ok() : Results.NotFound();
    } catch (Exception ex) {
        Console.WriteLine($"[LABREPORTS][ERROR][PUT] {ex.Message}\n{ex.StackTrace}");
        return Results.Problem("Failed to update lab report: " + ex.Message, statusCode: 500);
    }
});

// ------------ Appointment endpoints -------------

app.MapGet("/api/patients/{pid:int}/appointments", async (int pid) =>
{
    using var db = new SqlConnection(cs);
    var appts = await db.QueryAsync<Appointment>(
        "SELECT * FROM dbo.Appointments WHERE PatientId = @pid ORDER BY Date DESC, Time DESC", 
        new { pid });
    return Results.Ok(appts);
});

app.MapPost("/api/patients/{pid:int}/appointments", async (int pid, AppointmentInput input) =>
{
    using var db = new SqlConnection(cs);
    // Fetch patient name from DB
    var patient = await db.QuerySingleOrDefaultAsync<Patient>("SELECT * FROM dbo.Patients WHERE Id = @id", new { id = pid });
    var patientName = patient?.Name ?? string.Empty;
    var id = await db.ExecuteScalarAsync<int>(@"
        INSERT INTO dbo.Appointments (PatientId, Date, Time, Provider, Reason, DoctorNotes, Remedy, PatientName, DoctorName, DoctorId, Duration)
        VALUES (@PatientId, @Date, @Time, @Provider, @Reason, @DoctorNotes, @Remedy, @PatientName, @DoctorName, @DoctorId, @Duration);
        SELECT SCOPE_IDENTITY();",
        new { 
            PatientId = pid, 
            input.Date, 
            input.Time, 
            input.Provider, 
            input.Reason, 
            input.DoctorNotes, 
            input.Remedy,
            PatientName = patientName,
            input.DoctorName,
            input.DoctorId,
            input.Duration
        });
    return Results.Created($"/api/patients/{pid}/appointments/{id}", new { id });
});
                    
app.MapPost("/api/appointments/check-conflict", async ([FromBody] AppointmentInput input) =>
{
    using var db = new SqlConnection(cs);
    // Find all appointments for this doctor on the same date
    var appts = await db.QueryAsync<Appointment>(
        "SELECT * FROM dbo.Appointments WHERE DoctorId = @DoctorId AND Date = @Date",
        new { input.DoctorId, input.Date });
    var newStart = DateTime.Parse(input.Date.ToString("yyyy-MM-dd") + "T" + (input.Time ?? "00:00"));
    var newEnd = newStart.AddMinutes(input.Duration);
    foreach (var appt in appts)
    {
        var apptStart = DateTime.Parse(appt.Date.ToString("yyyy-MM-dd") + "T" + (appt.Time ?? "00:00"));
        var apptDuration = appt.Duration ?? 30;
        var apptEnd = apptStart.AddMinutes(apptDuration);
        if (newStart < apptEnd && newEnd > apptStart)
        {
            // Fetch patient name from DB for the conflicting appointment
            var patient = await db.QuerySingleOrDefaultAsync<Patient>("SELECT * FROM dbo.Patients WHERE Id = @id", new { id = appt.PatientId });
            var patientName = patient?.Name ?? string.Empty;
            return Results.Ok(new { conflict = true, patientName });
        }
    }
    return Results.Ok(new { conflict = false });
});

app.MapDelete("/api/patients/{pid:int}/appointments/{id:int}", async (int pid, int id) =>
{
    using var db = new SqlConnection(cs);
    var rows = await db.ExecuteAsync("DELETE FROM dbo.Appointments WHERE Id = @id AND PatientId = @pid", new { pid, id });
    return rows == 0 ? Results.NotFound() : Results.Ok();
});

app.MapGet("/api/appointments/doctor/{doctorId:int}/today", async (int doctorId) =>
{
    using var db = new SqlConnection(cs);
    var today = DateTime.Today;
    var appts = await db.QueryAsync<Appointment>(
        "SELECT * FROM dbo.Appointments WHERE DoctorId = @doctorId AND CAST(Date AS DATE) = @today ORDER BY Time ASC",
        new { doctorId, today });
    return Results.Ok(appts);
});

app.MapGet("/api/appointments/doctor/{doctorId:int}", async (int doctorId) =>
{
    using var db = new SqlConnection(cs);
    var appts = await db.QueryAsync<Appointment>(
        "SELECT * FROM dbo.Appointments WHERE DoctorId = @doctorId ORDER BY Date, Time",
        new { doctorId });
    return Results.Ok(appts);
});

// Health check
app.MapGet("/ping", () => "pong");

// ------------ Reminder Endpoints -------------
app.MapPost("/api/reminders/send", async (HttpRequest req, [FromServices] IOptions<TwilioOptions> twilioOptions) => {
    var reminder = await req.ReadFromJsonAsync<ReminderRequest>();
    if (reminder == null || string.IsNullOrWhiteSpace(reminder.PhoneNumber) || string.IsNullOrWhiteSpace(reminder.Message))
        return Results.BadRequest(new { error = "Missing phone number or message" });

    var options = twilioOptions.Value;
    Twilio.TwilioClient.Init(options.AccountSid, options.AuthToken);
    try {
        var message = await Twilio.Rest.Api.V2010.Account.MessageResource.CreateAsync(
            to: new Twilio.Types.PhoneNumber(reminder.PhoneNumber),
            from: new Twilio.Types.PhoneNumber(options.FromNumber),
            body: reminder.Message
        );
        Console.WriteLine($"[REMINDER] Sent to {reminder.PhoneNumber}: {reminder.Message} (SID: {message.Sid})");
        return Results.Ok(new { success = true, sid = message.Sid, message = "Reminder sent via Twilio" });
    } catch (Exception ex) {
        Console.WriteLine($"[REMINDER][ERROR] Failed to send to {reminder.PhoneNumber}: {ex.Message}");
        return Results.Problem($"Twilio error: {ex.Message}", statusCode: 500);
    }
});

// Static files
var defaults = new DefaultFilesOptions();
defaults.DefaultFileNames.Clear();
defaults.DefaultFileNames.Add("login.html");
app.UseDefaultFiles(defaults);
app.UseStaticFiles();

// Fallback for deep links
app.MapFallbackToFile("login.html");

app.Run();

// ------------ Record & option types -------------
class TwilioOptions
{
    public string AccountSid { get; set; } = string.Empty;
    public string AuthToken { get; set; } = string.Empty;
    public string FromNumber { get; set; } = string.Empty;
}

record ReminderRequest(string PhoneNumber, string Message);

// ------------ Appointment record types -------------
record Appointment(int Id, int PatientId, DateTime Date, string? Time, string Provider, string? Reason, string? DoctorNotes, string? Remedy, string? PatientName, string? DoctorName, int? DoctorId, int? Duration);
record AppointmentInput(DateTime Date, string? Time, string Provider, string? Reason, string? DoctorNotes, string? Remedy, string PatientName, string DoctorName, int DoctorId, int Duration);

// ------------ Medical Summary record types -------------
record Medication(string Name, string Dosage, string Duration);

record MedicalSummary(
    int Id,
    int PatientId,
    DateTime VisitDate,
    string ChiefComplaint,
    string? HistoryOfPresentIllness,
    string? PastMedicalHistory,
    string? FamilyHistory,
    string? SocialHistory,
    string? Allergies,
    string? VitalSigns,
    string? DoctorName,
    string? Specialization,
    string? VisitTime,
    string? DoctorNotes,
    List<Medication>? Medications,
    string? NextVisitDate,
    string? SpecialInstructions
);

record MedicalSummaryInput(
    DateTime VisitDate,
    string ChiefComplaint,
    string? HistoryOfPresentIllness = null,
    string? PastMedicalHistory = null,
    string? FamilyHistory = null,
    string? SocialHistory = null,
    string? Allergies = null,
    string? VitalSigns = null,
    string? DoctorName = null,
    string? Specialization = null,
    string? VisitTime = null,
    string? DoctorNotes = null,
    List<Medication>? Medications = null,
    string? NextVisitDate = null,
    string? SpecialInstructions = null
);

// ------------ Patient record types -------------
record LoginRequest(string Username, string Password, string CaptchaId, string Captcha);
record Doctor(int Id, string Name, string Specialization, string Username, string PasswordHash, string PasswordSalt);
record DoctorInput(string Name, string Specialization, string Username, string Password);
record Patient(int Id, string Name, int? Age, string? Gender, string? Contact, string? Note, int? DoctorId, string? Specialization);
record PatientInput(string Name, int? Age, string? Gender, string? Contact, string? Note, int? DoctorId, string? Specialization);

// LabReport records for lab endpoints
record LabReport(
    int LabReportID,
    int PatientID,
    DateTime ReportDate,
    string TestName,
    string TestResult,
    string ReferenceRange,
    string Units,
    int DoctorID,
    string Notes,
    string? PhysiologicBasis,
    string? Interpretation,
    string? Comments,
    string? PhoneNumber,
    DateTime CreatedAt,
    DateTime UpdatedAt,
    DateTime? DateOfVisit
)
{
    // Parameterless constructor for Dapper
    public LabReport() : this(0, 0, DateTime.MinValue, string.Empty, string.Empty, string.Empty, string.Empty, 0, string.Empty, null, null, null, null, DateTime.MinValue, DateTime.MinValue, null) { }
}

record LabReportInput(
    int PatientID,
    DateTime ReportDate,
    string TestName,
    string TestResult,
    string ReferenceRange,
    string Units,
    int DoctorID,
    string Notes,
    string? PhysiologicBasis,
    string? Interpretation,
    string? Comments,
    string? PhoneNumber,
    DateTime CreatedAt,
    DateTime UpdatedAt,
    DateTime? DateOfVisit
);
