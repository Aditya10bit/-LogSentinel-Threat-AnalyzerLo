# pyrefly: ignore [missing-import]
from fastapi import FastAPI
# pyrefly: ignore [missing-import]
from fastapi.staticfiles import StaticFiles
from analyzer import analyze_logs
from generate_logs import generate_logs
import os

app = FastAPI(title="LogSentinel API")

@app.on_event("startup")
def startup_event():
    if not os.path.exists("access.log"):
        generate_logs()

# API Endpoints
@app.get("/api/stats")
def get_stats():
    stats, _ = analyze_logs("access.log")
    return stats

@app.get("/api/alerts")
def get_alerts():
    _, alerts = analyze_logs("access.log")
    # Return newest alerts first
    return list(reversed(alerts))

# Mount static files (Frontend)
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
