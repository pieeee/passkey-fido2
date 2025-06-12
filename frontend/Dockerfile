FROM node:20

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY vite.config.js ./

# Install dependencies
RUN npm install

# Copy source files
COPY src/ ./src/
COPY public/ ./public/
COPY index.html ./


# Build the app
RUN npm run build

# Start the app
CMD ["npm", "run", "dev", "--", "--host"]