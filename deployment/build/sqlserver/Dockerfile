# Custom Azure SQL Edge image with go-sqlcmd
FROM mcr.microsoft.com/azure-sql-edge:latest

USER root

# Install dependencies and go-sqlcmd
RUN apt-get update \
    && apt-get install -y gnupg curl apt-transport-https \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y sqlcmd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

USER mssql
