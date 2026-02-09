# Start the backend server
Set-Location $PSScriptRoot
Write-Host "Starting CTBA Backend Server..." -ForegroundColor Green
Write-Host "Server will run on http://localhost:8000" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""
python main.py
