Param(
    [string] = 'py',
    [string] = (Resolve-Path '..'),
    [switch]
)

Set-StrictMode -Version Latest
 = 'Stop'
Push-Location 
try {
    if () { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue dist, build }
    &  -m pip install --upgrade pip
    &  -m pip install -e .
    &  -m pip install pyinstaller

     = @(
        '--noconfirm',
        '--clean',
        '--collect-all', 'pytesseract',
        '--collect-all', 'cv2',
        '--hidden-import', 'cv2',
        '--hidden-import', 'numpy'
    )

    pyinstaller @Common windows/entry/rename_entry.py --name dashcam-rename
    pyinstaller @Common windows/entry/ingest_entry.py --name dashcam-ingest
    pyinstaller @Common windows/entry/report_entry.py --name dashcam-report
    pyinstaller @Common windows/entry/gui_entry.py --name dashcam-gui --windowed

    Write-Host 'Build complete. EXEs in dist\*' -ForegroundColor Green
    Write-Host 'Note: Install Tesseract-OCR separately on Windows and ensure it is on PATH.' -ForegroundColor Yellow
}
finally {
    Pop-Location
}
