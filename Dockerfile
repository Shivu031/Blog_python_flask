# FROM → Python installed

# WORKDIR /app → container folder

# COPY → copy files

# RUN pip install → install libs

# CMD → start your app


FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy dependencies
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project
COPY . .

# Expose Flask port
EXPOSE 5000

# Run app
CMD ["python", "main.py"]
