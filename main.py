# pyrefly: ignore [missing-import]
from fastapi import FastAPI
# pyrefly: ignore [missing-import]
from fastapi.staticfiles import StaticFiles
from analyzer import analyze_logs

app = FastAPI(title="LogSentinel API")

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
    # pyrefly: ignore [missing-import]
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
