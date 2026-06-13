# Planted vulnerabilities (fixture): floating 'latest' tag + runs as root (no USER).
FROM node:latest
COPY . /app
WORKDIR /app
CMD ["node", "config.js"]
