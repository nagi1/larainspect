FROM php:8.4-fpm-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl iproute2 nginx supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install pdo_mysql
RUN curl -fsSL https://raw.githubusercontent.com/nagi1/larainspect/master/install.sh | sh

WORKDIR /var/www/html

COPY demo/ /var/www/html
COPY demo/docker/normal/php-fpm-www.conf /usr/local/etc/php-fpm.d/www.conf
COPY demo/docker/normal/nginx-default.conf /etc/nginx/sites-available/default
COPY demo/docker/normal/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY demo/larainspect.yaml /etc/larainspect/config.yaml

RUN mkdir -p /run/php /var/log/supervisor \
    && chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache \
    && chmod -R 0755 /var/www/html \
    && chmod -R 0775 /var/www/html/storage /var/www/html/bootstrap/cache

EXPOSE 80

CMD ["supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
