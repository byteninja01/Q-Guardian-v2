# Q-Guardian Run Script

$BackendPy = "python"
if (Test-Path "backend\.venv\Scripts\python.exe") {
    $BackendPy = (Resolve-Path "backend\.venv\Scripts\python.exe").Path
    Write-Host "Using project virtualenv Python: $BackendPy" -ForegroundColor Green
} else {
    Write-Host "WARNING: backend\.venv not found - using system Python." -ForegroundColor Yellow
}

if (-not (Test-Path "frontend\node_modules")) {
    Write-Host "Installing frontend dependencies..." -ForegroundColor Yellow
    Push-Location frontend
    npm install
    Pop-Location
}

Write-Host "Starting Q-Guardian Backend..." -ForegroundColor DarkRed
$backendCmd = "cd '$PWD\backend'; & '$BackendPy' -m uvicorn app.main:app --reload --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd

Write-Host "Starting Q-Guardian Frontend..." -ForegroundColor Yellow
$frontendCmd = "cd '$PWD\frontend'; npm run dev"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd

Write-Host "Q-Guardian Platform is launching!" -ForegroundColor Cyan
Write-Host "Backend: http://localhost:8000"
Write-Host "Frontend: http://localhost:5173"


