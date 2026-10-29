# syntax=docker/dockerfile:1
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.29-alpine
RUN apk add --no-cache openssl
# Template wird beim Start per envsubst zu /etc/nginx/conf.d/default.conf (setzt ${HTTPS_PORT} ein)
COPY templates/default.conf.template /etc/nginx/templates/default.conf.template
COPY nginx/sophosstats.conf /etc/nginx/snippets/sophosstats.conf
ENV HTTPS_PORT=443 HTTPS_REDIRECT=true
COPY --chmod=755 docker-entrypoint-cert.sh /docker-entrypoint.d/05-cert.sh
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80 443
