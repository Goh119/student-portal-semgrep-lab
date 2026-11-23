# Student Portal – Lab 5 (Semgrep SAST)

A standalone Flask / SQLite student portal for running locally inside Kali Linux.

## Functions
- Student and lecturer login with hashed passwords, generic login errors, and basic login rate limiting
- Student dashboard with grades and attendance
- Student assignment upload; lecturer can view/download submissions
- Student ↔ lecturer messaging
- Profile update restricted to the signed-in user
- Audit events in an internal database (demonstration only)

## Run in VMware Kali Linux

```bash
cd ~/student_portal_lab5
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
python app_secure.py
```

Open **http://127.0.0.1:5000** inside Kali Firefox.

Demo credentials (local testing ONLY):

| Username | Password | Role |
| --- | --- | --- |
| `student1` | `Student@12345` | Student |
| `student2` | `Student@12345` | Student |
| `lecturer1` | `Lecturer@12345` | Lecturer |

The SQLite database is automatically created at `instance/portal.db` on first startup. Uploaded files are stored under `instance/uploads/` and not publicly served by the Flask static folder.

To start with a fresh demo database, stop the server and run:

```bash
rm -rf instance
python app_secure.py
```

## Scan with Semgrep

With the Python environment activated:

```bash
python -m pip install semgrep
semgrep scan --config auto app_secure.py
semgrep scan --config auto app_secure.py --json -o semgrep-results.json
python semgrep_summary.py
```

The report exports findings, severity, affected files, and rule IDs, then suggests manually reviewing each finding. The script does not invent vulnerabilities if the scan finds zero.

## Important limits / security notes

- This is a local teaching prototype, **not a production-hardened university application**.
- `app.run()` is for local development only. Do not use `--host 0.0.0.0` or expose port 5000 to the public Internet.
- Demo passwords and account addresses are intentionally published for the lab and must never be reused in a real deployment.
- Session keys are randomly generated per application start unless `FLASK_SECRET_KEY` is set, which logs everyone out on restart.
- Secure-cookie flag requires HTTPS; set `USE_HTTPS=1` only after setting up TLS.
- There is **no real email MFA or external Identity Provider**. Those were optional external services in the earlier DFD and require separate configuration/integration.
- The simplistic single-process login-rate limit is not a production substitute for centralized rate limiting.
- Format signature checking is a demonstration control; it is **not malware scanning** and does not guarantee file safety.
- SAST can return zero findings; this does not establish that the application is free of vulnerabilities.
