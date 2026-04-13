FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --production --no-audit --no-fund

COPY . .

RUN mkdir -p /data

ENV NODE_ENV=production
ENV PORT=8080
ENV TOKEN_STORAGE_PATH=/data/tokens.json

EXPOSE 8080

CMD ["node", "server.js"]
