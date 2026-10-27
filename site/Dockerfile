FROM node:22-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV NODE_ENV=production PORT=3000 BANCO=/app/dados/ocs.sqlite
VOLUME ["/app/dados"]
EXPOSE 3000
CMD ["sh", "-c", "node seed.js && node server.js"]
