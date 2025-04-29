// run in virtual env
python3 -m venv venv
source venv/bin/activate    # macOS/Linux
venv\Scripts\activate     # Windows

// download requirements
pip install -r requirements.txt

// run web
flask run --host=0.0.0.0 --port=5050
