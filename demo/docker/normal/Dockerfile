FROM ubuntu:25.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        nginx \
        php8.4-cli \
        php8.4-fpm \
        php8.4-mbstring \
        php8.4-mysql \
        php8.4-xml \
        supervisor \
        ufw \
    && sed -i 's/^ENABLED=.*/ENABLED=no/' /etc/ufw/ufw.conf \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | sh

WORKDIR /var/www/html

COPY demo/ /var/www/html
COPY demo/docker/normal/php-fpm-www.conf /etc/php/8.4/fpm/pool.d/www.conf
COPY demo/docker/normal/nginx-default.conf /etc/nginx/sites-available/default
COPY demo/docker/normal/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY demo/larainspect.yaml /etc/larainspect/config.yaml

RUN mkdir -p /run/php /var/log/supervisor \
    && chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache \
    && chmod -R 0755 /var/www/html \
    && chmod -R 0775 /var/www/html/storage /var/www/html/bootstrap/cache

EXPOSE 80

CMD ["supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
