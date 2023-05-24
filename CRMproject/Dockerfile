FROM python:3.11.3-alpine3.17

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ENV PIP_TRUSTED_HOST=pypi.python.org

# Create and set the working directory
RUN mkdir /app
WORKDIR /app

# Update package index
RUN apk update

# Install system dependencies and build tools
RUN apk --no-cache add openssl
RUN apk --no-cache add postgresql-dev
RUN apk --no-cache add libffi-dev
RUN apk --no-cache add wget
RUN apk --no-cache add build-base


# Download and install ncurses 6.4 from source
RUN set -e; set -x; \
    apk --no-cache add openssl postgresql-dev libffi-dev wget build-base && \
    wget https://invisible-mirror.net/archives/ncurses/current/ncurses-6.4-20230408.tgz && \
    tar -xzf ncurses-6.4-20230408.tgz && \
    cd ncurses-6.4-20230408 && \
    ./configure --prefix=/usr/local && \
    make && \
    make install && \
    cd .. && \
    rm -rf ncurses-6.4-20230408 ncurses-6.4-20230408.tgz

# Set Django settings module environment variable
ENV DJANGO_SETTINGS_MODULE CRMproject.settings

# Copy the .env file
COPY .env /app/

# Determine the encryption key from the build argument
ARG encryption_key

# Check if the encryption key is provided
RUN if [ -z "$encryption_key" ]; then \
      echo "Error: Encryption key not provided."; \
      exit 1; \
    fi

# Encrypt the .env file using the encryption key
RUN openssl aes-256-cbc -e -in .env -out .env.encrypted -k $encryption_key

# Remove the original .env file
RUN rm .env

# Upgrade pip to the latest version
RUN pip install --trusted-host pypi.python.org --upgrade pip -v

# Install any needed packages specified in requirements.txt
COPY requirements.txt /app/
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Remove build-base and other unnecessary packages
RUN apk del build-base wget

# Copy the rest of the application code
COPY . /app/

# Expose the port the app runs on
EXPOSE 8000

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "CRMproject.wsgi:application"]