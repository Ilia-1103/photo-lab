FROM node:24-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY public ./public
COPY scripts ./scripts
ENV HOST=0.0.0.0 PORT=4173 DB_PATH=/app/data/photo-lab.sqlite
RUN mkdir -p /app/data && chown -R node:node /app
VOLUME ["/app/data"]
EXPOSE 4173
USER node
CMD ["node", "src/server.js"]
