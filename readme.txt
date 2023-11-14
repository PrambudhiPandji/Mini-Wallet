dependency install:
pip install uvicorn[standard]
pip install python-multipart
pip install python-jose[cryptography]
pip install passlib[bcrpyt]
pip install pyjsend 
pip install fastapi 

How to run:
uvicorn main:app --reload 

#reload is to reload the server automatically when saving