FROM php:8.4-fpm-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl iproute2 nginx supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install pdo_mysql
RUN curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | sh

WORKDIR /var/www/html

COPY demo/ /var/www/html
COPY demo/docker/vulnerable/php-fpm-www.conf /usr/local/etc/php-fpm.d/www.conf
COPY demo/docker/vulnerable/nginx-default.conf /etc/nginx/sites-available/default
COPY demo/docker/vulnerable/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY demo/larainspect.yaml /etc/larainspect/config.yaml

RUN mkdir -p /run/php /var/log/supervisor /var/www/html/public/uploads /var/www/html/public/backups \
    && chown -R root:root /var/www/html \
    && chmod -R 0777 /var/www/html /run/php

EXPOSE 80 9000 9001

CMD ["supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
