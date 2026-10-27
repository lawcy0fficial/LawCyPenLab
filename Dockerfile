# LawCypenLab :: AEGIS STATION — training image.
# FOR AUTHORIZED SECURITY TRAINING USE ONLY. Do not expose publicly.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p uploads plugins_store instance

EXPOSE 5000

# Seed a fresh database on container start, then launch the app.
CMD ["sh", "-c", "python3 seed.py && python3 app.py"]
