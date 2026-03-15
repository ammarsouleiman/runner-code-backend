FROM node:22-alpine

# Install build tools required for better-sqlite3 native compilation
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files first for better layer caching
COPY package*.json ./

# Install dependencies and rebuild native modules for Linux
RUN npm ci && npm rebuild better-sqlite3 --build-from-source

# Copy application source
COPY . .

EXPOSE 3001

CMD ["node", "server.js"]
