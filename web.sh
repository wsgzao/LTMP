#!/bin/bash

## alias
ltmp_local=$(cd "$(dirname "$0")"; pwd)
mkdir -p /app/{local,data}
unalias cp 
ltmp_init=$ltmp_local/init/
ltmp_src=$ltmp_local/src/

## system

#history
cp ${ltmp_init}bashrc /etc/
#time
rm -rf /etc/localtime
ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
#maildrop
sed -i 's/MAILTO=root/MAILTO=""/g' /etc/crontab
service crond restart
#selinux
setenforce 0
sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config 
#limits
echo ulimit -SHn 65535 >> /etc/profile
source /etc/profile
cp ${ltmp_init}limits.conf /etc/security/
#tcp
cp ${ltmp_init}sysctl.conf  /etc/
#yum
yum -y install yum-fastestmirror
yum remove httpd mysql mysql-server php php-cli php-common php-devel php-gd  -y
yum install -y wget gcc gcc-c++ openssl* curl curl-devel libxml2 libxml2-devel glibc glibc-devel glib2 glib2-devel gd gd2 gd-devel gd2-devel libaio autoconf libjpeg libjpeg-devel libpng libpng-devel freetype freetype-devel 
#download

cd /app/local
##PCRE - Perl Compatible Regular Expressions
#wget "ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.37.tar.gz"
##Tengine
#wget "http://tengine.taobao.org/download/tengine-2.1.0.tar.gz"
##MySQL
#wget "https://downloads.mariadb.com/archives/mysql-5.6/mysql-5.6.25-linux-glibc2.5-x86_64.tar.gz"
##PHP
#wget "http://cn2.php.net/distributions/php-5.6.11.tar.gz"
##Mhash
#wget "http://downloads.sourceforge.net/mhash/mhash-0.9.9.9.tar.gz"
##libmcrypt
#wget "http://downloads.sourceforge.net/mcrypt/libmcrypt-2.5.8.tar.gz"
##Mcrypt
#wget "http://downloads.sourceforge.net/mcrypt/mcrypt-2.6.8.tar.gz"

## soft
cd $ltmp_local
#pcre
tar zxvf pcre-8.37.tar.gz 1> /dev/null 
cd pcre-8.37
./configure
make && make install
cd ../
#tengine
groupadd www
useradd -g www www
#°²×°Tengine
cd $ltmp_local
tar zxvf tengine-2.1.0.tar.gz 1> /dev/null 
cd tengine-2.1.0
./configure --user=www --group=www \
--prefix=/app/local/nginx \
--with-http_stub_status_module \
--with-http_ssl_module \
--with-pcre=${ltmp_local}/pcre-8.37
make && make install
cd ../
#nginx config
cd $ltmp_local
cp ${ltmp_init}nginx.conf /app/local/nginx/conf/
cp -r ${ltmp_init}vhosts /app/local/nginx/conf/
mkdir -p /app/data/localhost
chmod +w /app/data/localhost
echo "<?php phpinfo();?>" > /app/data/localhost/phpinfo.php
chown -R www:www /app/data/localhost
echo 'export PATH=$PATH:/app/local/nginx/sbin'>>/etc/profile && source /etc/profile
cp ${ltmp_init}nginx /etc/rc.d/init.d/
chmod +x /etc/init.d/nginx
ulimit -SHn 65535
service nginx start
#libmcrypt
cd $ltmp_src
tar -zxvf libmcrypt-2.5.8.tar.gz 1> /dev/null 
cd libmcrypt-2.5.8
./configure
make && make install
cd ../
#mhash
cd $ltmp_src
tar -zxvf mhash-0.9.9.9.tar.gz 1> /dev/null 
cd mhash-0.9.9.9
./configure
make && make install
cd ../
#mcrypt
cd $ltmp_src
tar -zxvf mcrypt-2.6.8.tar.gz 1> /dev/null 
cd mcrypt-2.6.8
LD_LIBRARY_PATH=/usr/local/lib ./configure
make && make install
cd ../
#php
cd $ltmp_local
tar zxvf php-5.5.27.tar.gz 1> /dev/null 
cd php-5.5.27
./configure --prefix=/app/local/php \
--with-config-file-path=/app/local/php/etc \
--enable-fpm \
--enable-mbstring \
--with-mhash \
--with-mcrypt \
--with-curl \
--with-openssl \
--with-mysql=mysqlnd \
--with-mysqli=mysqlnd \
--with-pdo-mysql=mysqlnd
make && make install
#memcache
cd $ltmp_src
tar zxvf memcache-3.0.8.tgz  1> /dev/null 
cd memcache-3.0.8
/app/local/php/bin/phpize
./configure --enable-memcache \
--with-php-config=/app/local/php/bin/php-config \
--with-zlib-dir
make && make install
#mongo
cd $ltmp_src
tar zxvf mongo-1.6.10.tgz  1> /dev/null 
cd mongo-1.6.10
/app/local/php/bin/phpize
./configure --with-php-config=/app/local/php/bin/php-config
make && make install
#redis
cd $ltmp_src
#redis
tar zxvf redis-2.2.7.tgz  1> /dev/null 
cd redis-2.2.7
/app/local/php/bin/phpize
./configure --with-php-config=/app/local/php/bin/php-config
make && make install
#php-fpm
cp ${ltmp_init}php.ini /app/local/php/etc/
cp ${ltmp_init}php-fpm.conf /app/local/php/etc/
echo 'export PATH=$PATH:/app/local/php/bin'>>/etc/profile && source /etc/profile
touch /app/local/php/var/log/php-fpm.slow.log
cp ${ltmp_local}/php-5.5.27/sapi/fpm/init.d.php-fpm /etc/rc.d/init.d/php-fpm
chmod +x /etc/rc.d/init.d/php-fpm
service php-fpm start
