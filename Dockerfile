FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH deobs.DeobfuScripter

# Install python dependancies
RUN pip install --no-cache-dir --user beautifulsoup4 lxml && rm -rf ~/.cache/pip

# Copy Crowbar service code
WORKDIR /opt/al_service
COPY . .