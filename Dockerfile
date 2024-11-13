# Use official Python runtime as the base image
FROM python:3.9-slim

# Set environment variables
ENV PORT=5000

# Set working directory in container
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Make port 5000 available to the world outside the container
EXPOSE $PORT

# Command to run the application
CMD ["python", "app.py"]
