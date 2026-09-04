# Q-Guardian Run Script

Write-Host "Starting Q-Guardian Backend..." -ForegroundColor DarkRed
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd backend; python -m uvicorn app.main:app --reload --port 8000"

Write-Host "Starting Q-Guardian Frontend..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd frontend; npm run dev"

Write-Host "Q-Guardian Platform is launching!" -ForegroundColor Cyan
Write-Host "Backend: http://localhost:8000"
Write-Host "Frontend: http://localhost:5173"
