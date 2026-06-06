FROM nginx:alpine

# Remove default nginx config and static files
RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/default.conf

# Copy our nginx config
COPY docker/frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Copy pre-built React app
COPY sharingan-frontend/dist/ /usr/share/nginx/html/

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
    CMD wget -qO- http://127.0.0.1:5173/ || exit 1

EXPOSE 5173
