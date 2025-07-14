# SimpleBackend

This project is a backend service for a healthcare portal. It is built with .NET and provides APIs and static content for managing healthcare-related data such as patients, appointments, doctors, labs, and more.

## Features
- Patient management (add, delete, view)
- Appointment scheduling
- Doctor and staff management
- Lab and insurance information
- Medical summaries and reports
- Patient reminders (Twilio integration)
- Admin dashboard

## Project Structure
- `Program.cs`: Main entry point for the backend service.
- `wwwroot/`: Static web assets (HTML, JS, images) for the portal UI.
- `bin/` and `obj/`: Build output and intermediate files.
- `twilio.json`: Configuration for Twilio reminders.

## Setup
1. **.NET SDK**: Make sure you have the .NET 8.0+ SDK installed.
2. **Restore dependencies**: Run `dotnet restore` in the `SimpleBackend` directory.
3. **Build**: Run `dotnet build`.
4. **Run**: Use `dotnet run` to start the backend server.
5. **Access**: Open the HTML files in `wwwroot/` for the frontend, or connect your frontend app to the backend APIs.

## Configuration
- Update `twilio.json` with your Twilio credentials for SMS reminders.
- Database connection strings and other secrets should be managed securely (not included in this repo).

## License
This project is for educational/demo purposes. 