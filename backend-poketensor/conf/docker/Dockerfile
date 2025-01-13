# Use the official Python image
FROM python:3.11-slim

# Set the working directory
WORKDIR .

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port (optional, helps with clarity)
EXPOSE 8000

# Run the app with Uvicorn
CMD ["bash", "-c", "alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port 8000"]