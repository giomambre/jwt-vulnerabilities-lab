FROM python:3.12-slim

WORKDIR /lab

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY exploits ./exploits
COPY docs ./docs
COPY README.md .

EXPOSE 5000

CMD ["python", "-m", "flask", "--app", "app.main", "run", "--host", "0.0.0.0", "--port", "5000"]
