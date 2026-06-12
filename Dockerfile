FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --production --no-audit --no-fund

COPY . .

RUN mkdir -p /data

ENV NODE_ENV=production
ENV PORT=8080
# Diretório (não arquivo!) — server.js faz path.join(TOKEN_STORAGE_PATH, ".bling-tokens.json")
ENV TOKEN_STORAGE_PATH=/data

EXPOSE 8080

CMD ["node", "server.js"]
