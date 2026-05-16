# LogSentinel: Lightweight SIEM & Threat Analyzer

A lightweight, self-contained Security Information and Event Management (SIEM) application built with Python, FastAPI, and vanilla JavaScript (Tailwind CSS + Chart.js). 

## Features
- **Mock Log Generation**: Automatically generates a web server `access.log` containing both normal traffic and malicious payloads (SQL Injection, XSS, and Brute Force attacks).
- **Threat Detection Engine**: Parses logs using regex to identify and categorize threats with assigned severity levels.
- **REST API**: FastAPI backend providing endpoints for log statistics and alert feeds.
- **Modern Dashboard**: A dark-mode, responsive web interface that visualizes threat distributions and displays a live alert feed.

## Tech Stack
- **Backend**: Python, FastAPI, Uvicorn
- **Frontend**: HTML5, Vanilla JavaScript, Tailwind CSS (CDN), Chart.js (CDN)

## Getting Started

### Prerequisites
- Python 3.8+

### Installation & Execution
1. Clone the repository and navigate to the project directory:
   ```bash
   cd log_sentinel
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Generate the mock logs (`access.log`):
   ```bash
   python generate_logs.py
   ```

4. Start the SIEM application:
   ```bash
   python main.py
   ```

5. Open your browser and navigate to `http://localhost:8000` to view the dashboard.

## API Endpoints
- `GET /api/stats` - Returns overall log statistics and threat distribution.
- `GET /api/alerts` - Returns a JSON list of all detected malicious activities.
