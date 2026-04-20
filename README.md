# Malware File Analyzer — College Major Project
## Dynamic Analysis powered by Hybrid Analysis API

---

## What Changed
- ✅ Hybrid Analysis API integrated (real dynamic sandbox)
- ✅ Files execute in real Windows VM on Hybrid Analysis servers
- ✅ Results show: behavioral signatures, network activity, processes
- ✅ Final score = 40% static + 60% dynamic (more accurate)
- ✅ Malware family identified from Hybrid Analysis database
- ✅ UI updated to show dynamic analysis section

---

## Setup

### 1. Install dependencies
```
pip install -r requirements.txt
```

### 2. Run the project
```
python run.py
```

### 3. Open browser
```
http://localhost:5000
```

---

## API Key Location
File: `backend/services/hybrid_analysis.py`
Line: `HYBRID_API_KEY = "your_key_here"`

---

## How Dynamic Analysis Works
1. File uploaded from browser
2. Backend sends file to Hybrid Analysis API
3. Hybrid Analysis runs file in real Windows 7 sandbox
4. Results come back (takes 2-5 minutes per file)
5. UI shows behavioral signatures, network activity, processes
6. PDF report generated with full results

---

## Note on Analysis Time
Dynamic analysis takes **2-5 minutes** per file because the file
actually executes in a real sandbox environment. This is normal.
The loading screen will show the current step.
