# Q-Guardian Run Script

$BackendPy = "python"
$VenvCandidates = @("backend\venv\Scripts\python.exe", "backend\.venv\Scripts\python.exe")
$FoundVenv = $VenvCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($FoundVenv) {
    $BackendPy = (Resolve-Path $FoundVenv).Path
    Write-Host "Using project virtualenv Python: $BackendPy" -ForegroundColor Green
} else {
    Write-Host "WARNING: no backend venv found (checked backend\venv and backend\.venv) - installing backend requirements into system Python." -ForegroundColor Yellow
    Push-Location backend
    python -m pip install -r requirements.txt
    Pop-Location
}

if (-not (Test-Path "frontend\node_modules")) {
    Write-Host "Installing frontend dependencies (first run only)..." -ForegroundColor Yellow
    Push-Location frontend
    npm install
    Pop-Location
}

Write-Host "Starting Q-Guardian Backend..." -ForegroundColor DarkRed
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd backend; $BackendPy -m uvicorn app.main:app --reload --port 8000"

Write-Host "Starting Q-Guardian Frontend..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd frontend; npm run dev"

Write-Host "Q-Guardian Platform is launching!" -ForegroundColor Cyan
Write-Host "Backend: http://localhost:8000"
Write-Host "Frontend: http://localhost:5173"
