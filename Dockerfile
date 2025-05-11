# Sử dụng image PHP chính thức
FROM php:8.1-apache

# Cài đặt các extension cần thiết
RUN docker-php-ext-install mysqli

# Cài đặt Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Cài đặt các thư viện bổ sung (nếu cần)
RUN apt-get update && apt-get install -y \
    libzip-dev unzip && \
    docker-php-ext-install zip

# Copy mã nguồn vào container
COPY . /var/www/html/

# Phân quyền cho thư mục
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Kích hoạt mod_rewrite của Apache
RUN a2enmod rewrite

# Expose cổng 80
EXPOSE 80