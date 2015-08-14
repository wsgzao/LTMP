![](//i.v2ex.co/Up79Hq7l.jpeg)

## 前言
现在很多朋友都了解或者已经在使用LNMP架构，一般可以理解为Linux Shell为CentOS/RadHat/Fedora/Debian/Ubuntu/等平台安装LNMP(Nginx/MySQL/PHP)，LNMPA(Nginx/MySQL/PHP/Apache)，LAMP(Apache/MySQL/PHP)等类似的开发或生产环境。我自己是从SuSE/Oracle商业化环境走出来的，对于开源的部署方案也是在一点一点摸索，我相信其中也必然包含某些坑爹的配置。这篇文章较为详细的描述了基于LTMP架构的部署过程，之后会再考虑独立各个模块分享细节和技巧，如果大家有更合适的配置实践手册欢迎一起分享，文章中的错误和改进点也请帮忙指点下哈。

>LTMP(CentOS/Tengine/MySQL/PHP)

---

## 更新历史

2015年08月04日 - 初稿

阅读原文 - http://wsgzao.github.io/post/ltmp/

扩展阅读

CentOS - http://www.centos.org/
Tengine - http://tengine.taobao.org/
Nginx - http://nginx.org/en/docs/
MySQL - http://www.mysql.com/
PHP - http://php.net/
LTMP索引 - http://wsgzao.github.io/index/#LTMP


---

## LTMP版本

1. CentOS_6.5_64
2. Tengine-2.1.0
3. MySQL_5.6.25
4. PHP_5.5.27
5. Apache_2.2.31(酱油)

##准备工作

>如果允许公网访问会方便很多

``` bash
#优化History历史记录
vi /etc/bashrc

#设置保存历史命令的文件大小
export HISTFILESIZE=1000000000
#保存历史命令条数
export HISTSIZE=1000000
#实时记录历史命令，默认只有在用户退出之后才会统一记录，很容易造成多个用户间的相互覆盖。
export PROMPT_COMMAND="history -a"
#记录每条历史命令的执行时间
export HISTTIMEFORMAT="%Y-%m-%d_%H:%M:%S "

#设置时区（可选）
rm -rf /etc/localtime
ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

#禁用NetworkManager（可选）
/etc/init.d/NetworkManager stop
chkconfig NetworkManager off
/etc/init.d/network restart

#关闭iptables（可选） 
/etc/init.d/iptables stop
chkconfig iptables off

#设置dns（可选）
echo "nameserver 114.114.114.114" > /etc/resolv.conf 

#关闭maildrop
#cd /var/spool/postfix/maildrop;ls | xargs rm -rf; 
sed 's/MAILTO=root/MAILTO=""/g' /etc/crontab
service crond restart

#关闭selinux
setenforce 0
sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config  


#文件打开数量，
echo ulimit -SHn 65535 >> /etc/profile
source /etc/profile

#修改最大进程和最大文件打开数限制
vi /etc/security/limits.conf
* soft nproc 11000
* hard nproc 11000
* soft nofile 655350
* hard nofile 655350

sed -i -e '/# End of file/i\* soft  nofile 65535\n* hard nofile 65535'  /etc/security/limits.conf

#优化TCP
vi /etc/sysctl.conf

#禁用包过滤功能 
net.ipv4.ip_forward = 0  
#启用源路由核查功能 
net.ipv4.conf.default.rp_filter = 1  
#禁用所有IP源路由 
net.ipv4.conf.default.accept_source_route = 0  
#使用sysrq组合键是了解系统目前运行情况，为安全起见设为0关闭
kernel.sysrq = 0  
#控制core文件的文件名是否添加pid作为扩展
kernel.core_uses_pid = 1  
#开启SYN Cookies，当出现SYN等待队列溢出时，启用cookies来处理
net.ipv4.tcp_syncookies = 1  
#每个消息队列的大小（单位：字节）限制
kernel.msgmnb = 65536  
#整个系统最大消息队列数量限制
kernel.msgmax = 65536  
#单个共享内存段的大小（单位：字节）限制，计算公式64G*1024*1024*1024(字节)
kernel.shmmax = 68719476736  
#所有内存大小（单位：页，1页 = 4Kb），计算公式16G*1024*1024*1024/4KB(页)
kernel.shmall = 4294967296  
#timewait的数量，默认是180000
net.ipv4.tcp_max_tw_buckets = 6000  
#开启有选择的应答
net.ipv4.tcp_sack = 1  
#支持更大的TCP窗口. 如果TCP窗口最大超过65535(64K), 必须设置该数值为1
net.ipv4.tcp_window_scaling = 1  
#TCP读buffer
net.ipv4.tcp_rmem = 4096 131072 1048576
#TCP写buffer
net.ipv4.tcp_wmem = 4096 131072 1048576   
#为TCP socket预留用于发送缓冲的内存默认值（单位：字节）
net.core.wmem_default = 8388608
#为TCP socket预留用于发送缓冲的内存最大值（单位：字节）
net.core.wmem_max = 16777216  
#为TCP socket预留用于接收缓冲的内存默认值（单位：字节）  
net.core.rmem_default = 8388608
#为TCP socket预留用于接收缓冲的内存最大值（单位：字节）
net.core.rmem_max = 16777216
#每个网络接口接收数据包的速率比内核处理这些包的速率快时，允许送到队列的数据包的最大数目
net.core.netdev_max_backlog = 262144  
#web应用中listen函数的backlog默认会给我们内核参数的net.core.somaxconn限制到128，而nginx定义的NGX_LISTEN_BACKLOG默认为511，所以有必要调整这个值
net.core.somaxconn = 262144  
#系统中最多有多少个TCP套接字不被关联到任何一个用户文件句柄上。这个限制仅仅是为了防止简单的DoS攻击，不能过分依靠它或者人为地减小这个值，更应该增加这个值(如果增加了内存之后)
net.ipv4.tcp_max_orphans = 3276800  
#记录的那些尚未收到客户端确认信息的连接请求的最大值。对于有128M内存的系统而言，缺省值是1024，小内存的系统则是128
net.ipv4.tcp_max_syn_backlog = 262144  
#时间戳可以避免序列号的卷绕。一个1Gbps的链路肯定会遇到以前用过的序列号。时间戳能够让内核接受这种“异常”的数据包。这里需要将其关掉
net.ipv4.tcp_timestamps = 0  
#为了打开对端的连接，内核需要发送一个SYN并附带一个回应前面一个SYN的ACK。也就是所谓三次握手中的第二次握手。这个设置决定了内核放弃连接之前发送SYN+ACK包的数量
net.ipv4.tcp_synack_retries = 1  
#在内核放弃建立连接之前发送SYN包的数量
net.ipv4.tcp_syn_retries = 1  
#开启TCP连接中time_wait sockets的快速回收
net.ipv4.tcp_tw_recycle = 1  
#开启TCP连接复用功能，允许将time_wait sockets重新用于新的TCP连接（主要针对time_wait连接）
net.ipv4.tcp_tw_reuse = 1  
#1st低于此值,TCP没有内存压力,2nd进入内存压力阶段,3rdTCP拒绝分配socket(单位：内存页)
net.ipv4.tcp_mem = 94500000 915000000 927000000   
#如果套接字由本端要求关闭，这个参数决定了它保持在FIN-WAIT-2状态的时间。对端可以出错并永远不关闭连接，甚至意外当机。缺省值是60 秒。2.2 内核的通常值是180秒，你可以按这个设置，但要记住的是，即使你的机器是一个轻载的WEB服务器，也有因为大量的死套接字而内存溢出的风险，FIN- WAIT-2的危险性比FIN-WAIT-1要小，因为它最多只能吃掉1.5K内存，但是它们的生存期长些。
net.ipv4.tcp_fin_timeout = 15  
#表示当keepalive起用的时候，TCP发送keepalive消息的频度（单位：秒）
net.ipv4.tcp_keepalive_time = 30  
#对外连接端口范围
net.ipv4.ip_local_port_range = 2048 65000
#表示文件句柄的最大数量
fs.file-max = 102400

#云主机上的优化

# Kernel sysctl configuration file for Red Hat Linux
#
# For binary values, 0 is disabled, 1 is enabled.  See sysctl(8) and
# sysctl.conf(5) for more details.

# Controls IP packet forwarding
net.ipv4.ip_forward = 0

# Controls source route verification
net.ipv4.conf.default.rp_filter = 1

# Do not accept source routing
net.ipv4.conf.default.accept_source_route = 0

# Controls the System Request debugging functionality of the kernel

# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
kernel.core_uses_pid = 1

# Controls the use of TCP syncookies
net.ipv4.tcp_syncookies = 1

# Disable netfilter on bridges.
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0

# Controls the default maxmimum size of a mesage queue
kernel.msgmnb = 65536

# Controls the maximum size of a message, in bytes
kernel.msgmax = 65536

# Controls the maximum shared segment size, in bytes
kernel.shmmax = 68719476736

# Controls the maximum number of shared memory segments, in pages
kernel.shmall = 4294967296
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.netfilter.nf_conntrack_max = 1000000
kernel.unknown_nmi_panic = 0
kernel.sysrq = 0
fs.file-max = 1000000
vm.swappiness = 10
fs.inotify.max_user_watches = 10000000
net.core.wmem_max = 327679
net.core.rmem_max = 327679
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

/sbin/sysctl -p

#自动选择最快的yum源
yum -y install yum-fastestmirror

#移除系统自带的rpm包的http mysql php
#yum remove httpd* php*
yum remove httpd mysql mysql-server php php-cli php-common php-devel php-gd  -y

#升级基础库
yum install -y wget gcc gcc-c++ openssl* curl curl-devel libxml2 libxml2-devel glibc glibc-devel glib2 glib2-devel gd gd2 gd-devel gd2-devel libaio autoconf libjpeg libjpeg-devel libpng libpng-devel freetype freetype-devel 

#yum安装基础必备环境包，可以先将yum源更换为阿里云的源
阿里：http://mirrors.aliyun.com/ 
搜狐：http://mirrors.sohu.com/ 
网易：http://mirrors.163.com/

#备份原先的yum源信息
mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup

#从阿里云镜像站下载centos6的repo
wget -O /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-6.repo

#最后yum重新生成缓存
yum makecache

#yum安装软件包（可选）
yum -y install tar zip unzip openssl* gd gd-devel gcc gcc-c++ autoconf libjpeg libjpeg-devel libpng libpng-devel freetype freetype-devel libxml2 libxml2-devel zlib zlib-devel glibc glibc-devel glib2 glib2-devel bzip2 bzip2-devel ncurses ncurses-devel curl curl-devel e2fsprogs e2fsprogs-devel krb5 krb5-devel libidn libidn-devel openssl openssl-devel openldap openldap-devel openldap-clients openldap-servers make libmcrypt libmcrypt-devel fontconfig fontconfig-devel libXpm* libtool* libxml2 libxml2-devel t1lib t1lib-devel



#定义目录结构，下载安装包
mkdir -p /app/{local,data}
cd /app/local

#PCRE - Perl Compatible Regular Expressions
wget "ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.37.tar.gz"
#Tengine
wget "http://tengine.taobao.org/download/tengine-2.1.0.tar.gz"
#MySQL
wget "https://downloads.mariadb.com/archives/mysql-5.6/mysql-5.6.25-linux-glibc2.5-x86_64.tar.gz"
#PHP
wget "http://cn2.php.net/distributions/php-5.6.11.tar.gz"
#Mhash
wget "http://downloads.sourceforge.net/mhash/mhash-0.9.9.9.tar.gz"
#libmcrypt
wget "http://downloads.sourceforge.net/mcrypt/libmcrypt-2.5.8.tar.gz"
#Mcrypt
wget "http://downloads.sourceforge.net/mcrypt/mcrypt-2.6.8.tar.gz"

```

## 配置Tengine

### 安装PCRE

``` bash
tar zxvf pcre-8.37.tar.gz
cd pcre-8.37
./configure
make && make install
cd ../

```

## 安装Tengine

``` bash
#添加www用户和组
groupadd www
useradd -g www www
#安装Tengine
tar zxvf tengine-2.1.0.tar.gz
cd tengine-2.1.0

./configure --user=www --group=www \
--prefix=/app/local/nginx \
--with-http_stub_status_module \
--with-http_ssl_module \
--with-pcre=/app/local/pcre-8.37

make && make install
cd ../

```

### 配置Nginx

>Nginx配置文件的优化很重要，理解每一步的意义

``` bash
#修改nginx.conf
vi /app/local/nginx/conf/nginx.conf

#用户和用户组
user  www www;
#工作进程，一般可以按CPU核数设定
worker_processes  auto;
worker_cpu_affinity auto;
#全局错误日志级别
# [ debug | info | notice | warn | error | crit ]
error_log  logs/error.log  error;
#PID文件位置
pid  logs/nginx.pid;
#更改worker进程的最大打开文件数限制，避免"too many open files"
worker_rlimit_nofile 65535;

#events事件指令是设定Nginx的工作模式及连接数上限
events{
     #epoll是Linux首选的高效工作模式
     use epoll;
     #告诉nginx收到一个新连接通知后接受尽可能多的连接
     multi_accept on;
     #用于定义Nginx每个进程的最大连接数
     worker_connections      65536;
}

#HTTP模块控制着nginx http处理的所有核心特性
http {
    include       mime.types;
    #设置文件使用的默认的MIME-type
    default_type  application/octet-stream;
    

    #对日志格式的设定，main为日志格式别名
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';
    #设置nginx是否将存储访问日志。关闭这个选项可以让读取磁盘IO操作更快
    access_log off;
    # access_log logs/access.log main buffer=16k;

    #开启gzip压缩，实时压缩输出数据流
    gzip on;
    #设置IE6或者更低版本禁用gzip功能
    gzip_disable "MSIE [1-6]\.";
    #前端的缓存服务器缓存经过gzip压缩的页面
    gzip_vary on;
    #允许压缩基于请求和响应的响应流
    gzip_proxied any;
    #设置数据的压缩等级
    gzip_comp_level 4;
    #设置对数据启用压缩的最少字节数
    gzip_min_length 1k;
    #表示申请16个单位为64K的内存作为压缩结果流缓存
    gzip_buffers 16 64k;
    #用于设置识别HTTP协议版本
    gzip_http_version 1.1;
    #用来指定压缩的类型
    gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;
     

    #打开缓存的同时也指定了缓存最大数目，以及缓存的时间
    open_file_cache max=200000 inactive=20s;
    #在open_file_cache中指定检测正确信息的间隔时间
    open_file_cache_valid 30s;
    #定义了open_file_cache中指令参数不活动时间期间里最小的文件数
    open_file_cache_min_uses 2;
    #指定了当搜索一个文件时是否缓存错误信息，也包括再次给配置中添加文件
    open_file_cache_errors on; 
 
    #设置允许客户端请求的最大的单个文件字节数
    client_max_body_size 30M;
    #设置客户端请求主体读取超时时间
    client_body_timeout 10;
    #设置客户端请求头读取超时时间
    client_header_timeout 10;
    #指定来自客户端请求头的headerbuffer大小
    client_header_buffer_size 32k;
    #设置客户端连接保持活动的超时时间
    keepalive_timeout 60;
    #关闭不响应的客户端连接
    reset_timedout_connection on;
    #设置响应客户端的超时时间
    send_timeout 10;
    #开启高效文件传输模式
    sendfile on;
    #告诉nginx在一个数据包里发送所有头文件，而不一个接一个的发送
    tcp_nopush on;
    #告诉nginx不要缓存数据，而是一段一段的发送
    tcp_nodelay on;
    #设置用于保存各种key（比如当前连接数）的共享内存的参数
    limit_conn_zone $binary_remote_addr zone=addr:5m; 
    #给定的key设置最大连接数，允许每一个IP地址最多同时打开有100个连接
    limit_conn addr 100; 
 
    #FastCGI相关参数是为了改善网站的性能：减少资源占用，提高访问速度
    fastcgi_buffers 256 16k;
    fastcgi_buffer_size 128k;
    fastcgi_connect_timeout 3s;
    fastcgi_send_timeout 120s;
    fastcgi_read_timeout 120s;
    server_names_hash_bucket_size 128;
    #不在error_log中记录不存在的错误
    log_not_found off;
    #关闭在错误页面中的nginx版本数字，提高安全性
    #server_tag Apache;
    server_tokens off;
    #tengine
    server_tag off;
    server_info off;

    #添加虚拟主机的配置文件
    include vhosts/*.conf;

    #负载均衡配置（暂时略过）
    #upstream test.com

    #设定虚拟主机配置
    server {
        #侦听80端口
        listen       80;
        #定义使用localhost访问
        server_name  localhost;
        #定义首页索引文件的名称
        index index.html index.htm index.php;
        #定义服务器的默认网站根目录位置
        root    /app/data/localhost/;
 
        #定义错误提示页面
        error_page  404              /404.html;
        error_page  500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
 
        #PHP 脚本请求全部转发到 FastCGI处理. 使用FastCGI默认配置.     
        location ~ .*\.(php|php5)?$ {
            fastcgi_pass   127.0.0.1:9000;
            fastcgi_index  index.php;
            include        fastcgi.conf;
        }
        
        #静态文件
        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf|ico)$
        {
            #过期30天，频繁更新可设置小一点
            expires      30d;
        }
 
        location ~ .*\.(js|css)?$
        {
            #过期1小时，不更新可设置大一些
            expires      1h;
        }
        #禁止访问
        location ~ /\. {
            deny all;
        }
    }
}

```

>简化配置文件
vi /app/local/nginx/conf/nginx.conf

``` bash

user  www www;
worker_processes auto;
worker_cpu_affinity auto;

error_log  logs/error.log  crit;
pid        logs/nginx.pid;

worker_rlimit_nofile 51200;
events
{
    use epoll;
    multi_accept on;
    worker_connections 51200;
}

http
{
    include       mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log off;
    #access_log logs/access.log main buffer=16k;

    server_names_hash_bucket_size 128;
    client_header_buffer_size 32k;
    large_client_header_buffers 4 32k;
    client_max_body_size 50M; 

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 60; 
    server_tokens off;
    server_tag off;
    server_info off;

    fastcgi_connect_timeout 300;
    fastcgi_send_timeout 300;
    fastcgi_read_timeout 300;
    fastcgi_buffer_size 64k;
    fastcgi_buffers 4 64k;
    fastcgi_busy_buffers_size 128k;
    fastcgi_temp_file_write_size 256k;

    #gzip on;
    #gzip_min_length  1k;
    #gzip_buffers     4 16k;
    #gzip_http_version 1.1;
    #gzip_comp_level 5;
    #gzip_types       text/plain application/x-javascript text/css application/xml;
    #gzip_vary on;

    include vhosts/*.conf;
}

```

>分离server写入vhosts
mkdir -p  /app/local/nginx/conf/vhosts/
vi /app/local/nginx/conf/vhosts/localhost.conf

``` bash
server {
    listen       80;
    server_name  localhost;
    index index.php index.html index.htm;
    access_log  logs/localhost.log  main;

    root    /app/data/localhost/;

    location / {
        index  index.php index.html index.htm;
    }

    #error_page  404              /404.html;
    #error_page  500 502 503 504  /50x.html;

    location = /50x.html {
        root   html;
    }

    location ~ .*\.(php|php5)?$ {
        fastcgi_pass   127.0.0.1:9000;
        fastcgi_index  index.php;
      #fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include        fastcgi.conf;
    }

    location ~ .*\.(gif|jpg|jpeg|png|bmp|swf|ico)$
    {
        expires      30d;
    }

    location ~ .*\.(js|css)?$
    {
        expires      1h;
    }

    location ~ /\. {
        deny all;
    }
}

```



``` bash
#检查语法
/app/local/nginx/sbin/nginx -t
# ./nginx -t
the configuration file /app/local/nginx/conf/nginx.conf syntax is ok
configuration file /app/local/nginx/conf/nginx.conf test is successful

#测试用例
mkdir -p /app/data/localhost
chmod +w /app/data/localhost
echo "<?php phpinfo();?>" > /app/data/localhost/phpinfo.php
chown -R www:www /app/data/localhost

#设置nginx系统变量
echo 'export PATH=$PATH:/app/local/nginx/sbin'>>/etc/profile && source /etc/profile

#测试访问
curl -I http://localhost

HTTP/1.1 200 OK
Server: Tengine/2.1.0
Date: Mon, 27 Jul 2015 06:42:25 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/5.6.11


```

### 添加Tengine到服务

>配置服务后便于统一管理
vi /etc/rc.d/init.d/nginx

``` bash
#!/bin/sh
 
# Source function library.
. /etc/rc.d/init.d/functions
 
# Source networking configuration.
. /etc/sysconfig/network
 
# Check that networking is up.
[ "$NETWORKING" = "no" ] && exit 0
 
nginx="/app/local/nginx/sbin/nginx"
prog=$(basename $nginx)
 
NGINX_CONF_FILE="/app/local/nginx/conf/nginx.conf"
 
[ -f /etc/sysconfig/nginx ] && . /etc/sysconfig/nginx
 
lockfile=/var/lock/subsys/nginx
 
make_dirs() {
   # make required directories
   user=`$nginx -V 2>&1 | grep "configure arguments:" | sed 's/[^*]*--user=\([^ ]*\).*/\1/g' -`
   if [ -z "`grep $user /etc/passwd`" ]; then
       useradd -M -s /bin/nologin $user
   fi
   options=`$nginx -V 2>&1 | grep 'configure arguments:'`
   for opt in $options; do
       if [ `echo $opt | grep '.*-temp-path'` ]; then
           value=`echo $opt | cut -d "=" -f 2`
           if [ ! -d "$value" ]; then
               # echo "creating" $value
               mkdir -p $value && chown -R $user $value
           fi
       fi
   done
}
 
start() {
    [ -x $nginx ] || exit 5
    [ -f $NGINX_CONF_FILE ] || exit 6
    make_dirs
    echo -n $"Starting $prog: "
    daemon $nginx -c $NGINX_CONF_FILE
    retval=$?
    echo
    [ $retval -eq 0 ] && touch $lockfile
    return $retval
}
 
stop() {
    echo -n $"Stopping $prog: "
    killproc $prog -QUIT
    retval=$?
    echo
    [ $retval -eq 0 ] && rm -f $lockfile
    return $retval
}
 
restart() {
    configtest || return $?
    stop
    sleep 1
    start
}
 
reload() {
    configtest || return $?
    echo -n $"Reloading $prog: "
    killproc $nginx -HUP
    RETVAL=$?
    echo
}
 
force_reload() {
    restart
}
 
configtest() {
  $nginx -t -c $NGINX_CONF_FILE
}
 
rh_status() {
    status $prog
}
 
rh_status_q() {
    rh_status >/dev/null 2>&1
}
 
case "$1" in
    start)
        rh_status_q && exit 0
        $1
        ;;
    stop)
        rh_status_q || exit 0
        $1
        ;;
    restart|configtest)
        $1
        ;;
    reload)
        rh_status_q || exit 7
        $1
        ;;
    force-reload)
        force_reload
        ;;
    status)
        rh_status
        ;;
    condrestart|try-restart)
        rh_status_q || exit 0
            ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart|try-restart|reload|force-reload|configtest}"
        exit 2
esac

```

``` bash
#修改执行权限
chmod +x /etc/init.d/nginx
ulimit -SHn 65535
service nginx start

```

## 安装MySQL

>注意目录和字符集等配置文件

``` bash
#解压mysql
mkdir -p /app/local/mysql
tar zxvf mysql-5.6.25-linux-glibc2.5-x86_64.tar.gz
mv mysql-5.6.25-linux-glibc2.5-x86_64/* /app/local/mysql
#增加mysql用户组
groupadd mysql
useradd -g mysql mysql
mkdir -p /app/data/mysql/data/
mkdir -p /app/data/mysql/binlog/
mkdir -p /app/data/mysql/relaylog/
chown -R mysql:mysql /app/data/mysql/
 #安装mysql
/app/local/mysql/scripts/mysql_install_db --basedir=/app/local/mysql --datadir=/app/data/mysql/data --user=mysql
#修改mysqld_safe配置路径
sed -i "s#/usr/local/mysql#/app/local/mysql#g" /app/local/mysql/bin/mysqld_safe

```

``` bash

#修改my.cnf配置文件
vi /app/local/mysql/my.cnf

[client]
character-set-server = utf8
port = 3306
socket = /tmp/mysql.sock

[mysql]
#prompt="(\u:HOSTNAME:)[\d]> "
prompt="\u@\h \R:\m:\s [\d]> "
no-auto-rehash

[mysqld]
server-id = 1
port = 3306
user = mysql
basedir = /app/local/mysql
datadir = /app/data/mysql/data
socket = /tmp/mysql.sock
log-error = /app/data/mysql/mysql_error.log
pid-file = /app/data/mysql/mysql.pid
sql_mode=NO_ENGINE_SUBSTITUTION,STRICT_TRANS_TABLES

default-storage-engine = InnoDB
max_connections = 512
max_connect_errors = 100000
table_open_cache = 512
external-locking = FALSE
max_allowed_packet = 32M
slow_query_log = 1
slow_query_log_file = /app/data/mysql/slow.log

open_files_limit = 10240
back_log = 600
join_buffer_size = 2M
read_rnd_buffer_size = 16M
sort_buffer_size = 2M
thread_cache_size = 300
query_cache_size = 128M
query_cache_limit = 2M
query_cache_min_res_unit = 2k
thread_stack = 192K
transaction_isolation = READ-COMMITTED
tmp_table_size = 246M
max_heap_table_size = 246M
long_query_time = 3
log-slave-updates
log-bin = /app/data/mysql/binlog/binlog
sync_binlog = 1
binlog_cache_size = 4M
binlog_format = MIXED
max_binlog_cache_size = 8M
max_binlog_size = 1G
relay-log-index = /app/data/mysql/relaylog/relaylog
relay-log-info-file = /app/data/mysql/relaylog/relaylog
relay-log = /app/data/mysql/relaylog/relaylog
expire_logs_days = 7
key_buffer_size = 128M
read_buffer_size = 1M
read_rnd_buffer_size = 16M
bulk_insert_buffer_size = 64M
myisam_sort_buffer_size = 128M
myisam_max_sort_file_size = 10G
myisam_repair_threads = 1
myisam_recover

innodb_additional_mem_pool_size = 16M
innodb_buffer_pool_size = 256M
innodb_data_file_path = ibdata1:1024M:autoextend
innodb_flush_log_at_trx_commit = 1
innodb_log_buffer_size = 16M
innodb_log_file_size = 256M
innodb_log_files_in_group = 2
innodb_max_dirty_pages_pct = 50
innodb_file_per_table = 1
innodb_locks_unsafe_for_binlog = 0

interactive_timeout = 120
wait_timeout = 120
 
skip-name-resolve
slave-skip-errors = 1032,1062,126,1114,1146,1048,1396

[mysqldump]
quick
max_allowed_packet = 32M

```

``` bash

#添加mysql到服务
vi /etc/rc.d/init.d/mysqld

#!/bin/sh
basedir=/app/local/mysql
datadir=/app/data/mysql/data
service_startup_timeout=900
lockdir='/var/lock/subsys'
lock_file_path="$lockdir/mysql"
mysqld_pid_file_path=/app/data/mysql/mysql.pid
if test -z "$basedir"
then
  basedir=/usr/local/mysql
  bindir=/usr/local/mysql/bin
  if test -z "$datadir"
  then
    datadir=/usr/local/mysql/data
  fi
  sbindir=/usr/local/mysql/bin
  libexecdir=/usr/local/mysql/bin
else
  bindir="$basedir/bin"
  if test -z "$datadir"
  then
    datadir="$basedir/data"
  fi
  sbindir="$basedir/sbin"
  libexecdir="$basedir/libexec"
fi
datadir_set=
lsb_functions="/lib/lsb/init-functions"
if test -f $lsb_functions ; then
  . $lsb_functions
else
  log_success_msg()
  {
    echo " SUCCESS! $@"
  }
  log_failure_msg()
  {
    echo " ERROR! $@"
  }
fi
 
PATH="/sbin:/usr/sbin:/bin:/usr/bin:$basedir/bin"
export PATH
 
mode=$1    # start or stop
 
[ $# -ge 1 ] && shift
 
 
other_args="$*"   # uncommon, but needed when called from an RPM upgrade action
           # Expected: "--skip-networking --skip-grant-tables"
           # They are not checked here, intentionally, as it is the resposibility
           # of the "spec" file author to give correct arguments only.
 
case `echo "testing\c"`,`echo -n testing` in
    *c*,-n*) echo_n=   echo_c=     ;;
    *c*,*)   echo_n=-n echo_c=     ;;
    *)       echo_n=   echo_c='\c' ;;
esac
 
parse_server_arguments() {
  for arg do
    case "$arg" in
      --basedir=*)  basedir=`echo "$arg" | sed -e 's/^[^=]*=//'`
                    bindir="$basedir/bin"
            if test -z "$datadir_set"; then
              datadir="$basedir/data"
            fi
            sbindir="$basedir/sbin"
            libexecdir="$basedir/libexec"
        ;;
      --datadir=*)  datadir=`echo "$arg" | sed -e 's/^[^=]*=//'`
            datadir_set=1
    ;;
      --pid-file=*) mysqld_pid_file_path=`echo "$arg" | sed -e 's/^[^=]*=//'` ;;
      --service-startup-timeout=*) service_startup_timeout=`echo "$arg" | sed -e 's/^[^=]*=//'` ;;
    esac
  done
}
 
wait_for_pid () {
  verb="$1"           # created | removed
  pid="$2"            # process ID of the program operating on the pid-file
  pid_file_path="$3" # path to the PID file.
 
  i=0
  avoid_race_condition="by checking again"
 
  while test $i -ne $service_startup_timeout ; do
 
    case "$verb" in
      'created')
        # wait for a PID-file to pop into existence.
        test -s "$pid_file_path" && i='' && break
        ;;
      'removed')
        # wait for this PID-file to disappear
        test ! -s "$pid_file_path" && i='' && break
        ;;
      *)
        echo "wait_for_pid () usage: wait_for_pid created|removed pid pid_file_path"
        exit 1
        ;;
    esac
 
    # if server isn't running, then pid-file will never be updated
    if test -n "$pid"; then
      if kill -0 "$pid" 2>/dev/null; then
        :  # the server still runs
      else
        # The server may have exited between the last pid-file check and now.  
        if test -n "$avoid_race_condition"; then
          avoid_race_condition=""
          continue  # Check again.
        fi
 
        # there's nothing that will affect the file.
        log_failure_msg "The server quit without updating PID file ($pid_file_path)."
        return 1  # not waiting any more.
      fi
    fi
 
    echo $echo_n ".$echo_c"
    i=`expr $i + 1`
    sleep 1
 
  done
 
  if test -z "$i" ; then
    log_success_msg
    return 0
  else
    log_failure_msg
    return 1
  fi
}
 
# Get arguments from the my.cnf file,
# the only group, which is read from now on is [mysqld]
if test -x ./bin/my_print_defaults
then
  print_defaults="./bin/my_print_defaults"
elif test -x $bindir/my_print_defaults
then
  print_defaults="$bindir/my_print_defaults"
elif test -x $bindir/mysql_print_defaults
then
  print_defaults="$bindir/mysql_print_defaults"
else
  # Try to find basedir in /etc/my.cnf
  conf=/etc/my.cnf
  print_defaults=
  if test -r $conf
  then
    subpat='^[^=]*basedir[^=]*=\(.*\)$'
    dirs=`sed -e "/$subpat/!d" -e 's//\1/' $conf`
    for d in $dirs
    do
      d=`echo $d | sed -e 's/[     ]//g'`
      if test -x "$d/bin/my_print_defaults"
      then
        print_defaults="$d/bin/my_print_defaults"
        break
      fi
      if test -x "$d/bin/mysql_print_defaults"
      then
        print_defaults="$d/bin/mysql_print_defaults"
        break
      fi
    done
  fi
 
  # Hope it's in the PATH ... but I doubt it
  test -z "$print_defaults" && print_defaults="my_print_defaults"
fi
 
#
# Read defaults file from 'basedir'.   If there is no defaults file there
# check if it's in the old (depricated) place (datadir) and read it from there
#
 
extra_args=""
if test -r "$basedir/my.cnf"
then
  extra_args="-e $basedir/my.cnf"
else
  if test -r "$datadir/my.cnf"
  then
    extra_args="-e $datadir/my.cnf"
  fi
fi
 
parse_server_arguments `$print_defaults $extra_args mysqld server mysql_server mysql.server`
 
#
# Set pid file if not given
#
if test -z "$mysqld_pid_file_path"
then
  mysqld_pid_file_path=$datadir/`hostname`.pid
else
  case "$mysqld_pid_file_path" in
    /* ) ;;
    * )  mysqld_pid_file_path="$datadir/$mysqld_pid_file_path" ;;
  esac
fi
 
case "$mode" in
  'start')
    # Start daemon
 
    # Safeguard (relative paths, core dumps..)
    cd $basedir
 
    echo $echo_n "Starting MySQL"
    if test -x $bindir/mysqld_safe
    then
      # Give extra arguments to mysqld with the my.cnf file. This script
      # may be overwritten at next upgrade.
      $bindir/mysqld_safe --datadir="$datadir" --pid-file="$mysqld_pid_file_path" $other_args >/dev/null 2>&1 &
      wait_for_pid created "$!" "$mysqld_pid_file_path"; return_value=$?
 
      # Make lock for RedHat / SuSE
      if test -w "$lockdir"
      then
        touch "$lock_file_path"
      fi
 
      exit $return_value
    else
      log_failure_msg "Couldn't find MySQL server ($bindir/mysqld_safe)"
    fi
    ;;
 
  'stop')
    # Stop daemon. We use a signal here to avoid having to know the
    # root password.
 
    if test -s "$mysqld_pid_file_path"
    then
      mysqld_pid=`cat "$mysqld_pid_file_path"`
 
      if (kill -0 $mysqld_pid 2>/dev/null)
      then
        echo $echo_n "Shutting down MySQL"
        kill $mysqld_pid
        # mysqld should remove the pid file when it exits, so wait for it.
        wait_for_pid removed "$mysqld_pid" "$mysqld_pid_file_path"; return_value=$?
      else
        log_failure_msg "MySQL server process #$mysqld_pid is not running!"
        rm "$mysqld_pid_file_path"
      fi
 
      # Delete lock for RedHat / SuSE
      if test -f "$lock_file_path"
      then
        rm -f "$lock_file_path"
      fi
      exit $return_value
    else
      log_failure_msg "MySQL server PID file could not be found!"
    fi
    ;;
 
  'restart')
    # Stop the service and regardless of whether it was
    # running or not, start it again.
    if $0 stop  $other_args; then
      $0 start $other_args
    else
      log_failure_msg "Failed to stop running server, so refusing to try to start."
      exit 1
    fi
    ;;
 
  'reload'|'force-reload')
    if test -s "$mysqld_pid_file_path" ; then
      read mysqld_pid <  "$mysqld_pid_file_path"
      kill -HUP $mysqld_pid && log_success_msg "Reloading service MySQL"
      touch "$mysqld_pid_file_path"
    else
      log_failure_msg "MySQL PID file could not be found!"
      exit 1
    fi
    ;;
  'status')
    # First, check to see if pid file exists
    if test -s "$mysqld_pid_file_path" ; then 
      read mysqld_pid < "$mysqld_pid_file_path"
      if kill -0 $mysqld_pid 2>/dev/null ; then 
        log_success_msg "MySQL running ($mysqld_pid)"
        exit 0
      else
        log_failure_msg "MySQL is not running, but PID file exists"
        exit 1
      fi
    else
      # Try to find appropriate mysqld process
      mysqld_pid=`pidof $libexecdir/mysqld`
 
      # test if multiple pids exist
      pid_count=`echo $mysqld_pid | wc -w`
      if test $pid_count -gt 1 ; then
        log_failure_msg "Multiple MySQL running but PID file could not be found ($mysqld_pid)"
        exit 5
      elif test -z $mysqld_pid ; then 
        if test -f "$lock_file_path" ; then 
          log_failure_msg "MySQL is not running, but lock file ($lock_file_path) exists"
          exit 2
        fi 
        log_failure_msg "MySQL is not running"
        exit 3
      else
        log_failure_msg "MySQL is running but PID file could not be found"
        exit 4
      fi
    fi
    ;;
    *)
      # usage
      basename=`basename "$0"`
      echo "Usage: $basename  {start|stop|restart|reload|force-reload|status}  [ MySQL server options ]"
      exit 1
    ;;
esac
 
exit 0

```

``` bash
#修改权限
chmod +x /etc/init.d/mysqld
service mysqld start

#增加MySQL系统环境变量
echo 'export PATH=$PATH:/app/local/mysql/bin'>>/etc/profile && source /etc/profile

#查看错误日志
tail -f /var/log/mysqld.log 

#用root账户登录并作简单的安全设置
/app/local/mysql/bin/mysql -uroot -p
直接回车空密码

```

``` sql
#进入数据库
use mysql;
#设置root密码
UPDATE mysql.user SET Password=password('root') WHERE User='root';
#清除root密码
update user set password='' where user='root';
#删除无名用户
DELETE FROM mysql.user WHERE User='';
#删除root远程访问（可选）
#DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
#删除“test”数据库
DROP database test;
#允许远程访问
update user set host='%' where user='root' AND host='localhost';
#查看所有用户权限
SELECT DISTINCT CONCAT('User: ''',user,'''@''',host,''';') AS query FROM mysql.user;
#立即生效并退出MYSQL命令窗体
FLUSH PRIVILEGES;QUIT;

```

## 安装Apache

``` bash
cd /app/local
tar zxvf httpd-2.2.29.tar.gz
cd httpd-2.2.29

./configure --prefix=/app/local/apache \
--enable-so \
--enable-rewrite \
--enable-modes-shared=most

make && make install 

vi /app/local/apache/conf/httpd.conf

#修改主机名
ServerName localhost:80
#查找AddType application/x-gzip .gz .tgz,在该行下面添加
AddType application/x-httpd-php .php
#查找DirectoryIndex index.html 把该行修改成
DirectoryIndex index.html index.htm index.php

/app/local/apache/bin/apachectl -t
cp /app/local/apache/bin/apachectl /etc/init.d/httpd


```

## 安装PHP

### PHP基础环境

``` bash
#yum安装或者使用下面源包编译安装
yum install libmcrypt libmcrypt-devel mcrypt mhash

#下载地址
http://sourceforge.net/projects/mcrypt/files/Libmcrypt/
http://sourceforge.net/projects/mcrypt/files/MCrypt/
http://sourceforge.net/projects/mhash/files/mhash/

#安装Libmcrypt
tar -zxvf libmcrypt-2.5.8.tar.gz
cd libmcrypt-2.5.8
./configure
make && make install
cd ../

3.安装mhash

tar -zxvf mhash-0.9.9.9.tar.gz
cd mhash-0.9.9.9
./configure
make && make install
cd ../

4.安装mcrypt

tar -zxvf mcrypt-2.6.8.tar.gz
cd mcrypt-2.6.8
LD_LIBRARY_PATH=/usr/local/lib ./configure
make && make install
cd ../

### 安装PHP

>extension根据需要定制，新增的OPcache建议暂时不要开启

``` bash
tar zxvf php-5.5.27.tar.gz
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
--with-pdo-mysql=mysqlnd \
--with-apxs2=/app/local/apache/bin/apxs 
#--enable-opcache

make && make install

#配置php.ini
cp php.ini-development /app/local/php/etc/php.ini

#设置时区
sed -i "s#;date.timezone =#date.timezone = Asia/Shanghai#g" /app/local/php/etc/php.ini
#防止nginx文件类型错误解析漏洞
sed -i "s#;cgi.fix_pathinfo=1#cgi.fix_pathinfo=0#g" /app/local/php/etc/php.ini
#禁止显示php版本的信息
sed -i "s#expose_php = On#expose_php = Off#g" /app/local/php/etc/php.ini
#禁用危险函数（可选）
#sed -i "s#disable_functions =#disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source#g" /app/local/php/etc/php.ini

#enable-opcache后设置（可选）
[OPcache]
zend_extension = opcache.so
opcache.enable=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=4000
opcache.revalidate_freq=1
opcache.fast_shutdown=1
opcache.enable_cli=1

```
### 配置php-fpm

``` bash
#编辑php-fpm
cp /app/local/php/etc/php-fpm.conf.default /app/local/php/etc/php-fpm.conf
vi /app/local/php/etc/php-fpm.conf

[global]
;错误日志
error_log = log/php-fpm.log
;错误日志级别
log_level = notice
[www]
;php-fpm监听端口
listen = 127.0.0.1:9000
;启动进程的帐户和组
user = www
group = www
;如果选择static，则由pm.max_children指定固定的子进程数。如果选择dynamic，则由后面3个参数动态决定
pm = dynamic
;子进程最大数
pm.max_children = 384
;启动时的进程数
pm.start_servers = 20
;保证空闲进程数最小值，如果空闲进程小于此值，则创建新的子进程
pm.min_spare_servers = 5
;保证空闲进程数最大值，如果空闲进程大于此值，此进行清理
pm.max_spare_servers = 35

;设置每个子进程重生之前服务的请求数。对于可能存在内存泄漏的第三方模块来说是非常有用的。如果设置为 '0' 则一直接受请求。等同于 PHP_FCGI_MAX_REQUESTS 环境变量。默认值: 0。
pm.max_requests = 1000
;每个子进程闲置多长时间就自杀
pm.process_idle_timeout = 10s
;设置单个请求的超时中止时间。该选项可能会对php.ini设置中的'max_execution_time'因为某些特殊原因没有中止运行的脚本有用。设置为 '0' 表示 'Off'.当经常出现502错误时可以尝试更改此选项。
request_terminate_timeout = 120
;当一个请求该设置的超时时间后，就会将对应的PHP调用堆栈信息完整写入到慢日志中。设置为 '0' 表示 'Off'
request_slowlog_timeout = 3s
;慢请求的记录日志,配合request_slowlog_timeout使用
slowlog = /app/local/php/var/log/php-fpm.slow.log
;设置文件打开描述符的rlimit限制。默认值: 系统定义值默认可打开句柄是1024，可使用 ulimit -n查看，ulimit -n 2048修改。
rlimit_files = 65535

```

``` bash

#设置php环境变量
echo 'export PATH=$PATH:/app/local/php/bin'>>/etc/profile && source /etc/profile
touch /app/local/php/var/log/php-fpm.slow.log

#添加php-fpm服务
cp /app/local/php-5.5.27/sapi/fpm/init.d.php-fpm /etc/rc.d/init.d/php-fpm
chmod +x /etc/rc.d/init.d/php-fpm
service php-fpm start

#设置开机自动启动服务
vi /etc/rc.local

ulimit -SHn 65535
service php-fpm start
service nginx start
service mysqld start

```

### 配置memcache/mongo/redis

>其它extension扩展都可以动态添加，没事的

``` bash
#memcache
cd /app/local
tar zxvf memcache-3.0.8.tgz
cd memcache-3.0.8
/app/local/php/bin/phpize
./configure --enable-memcache \
--with-php-config=/app/local/php/bin/php-config \
--with-zlib-dir
make && make install

#mongo
cd /app/local
tar zxvf mongo-1.6.10.tgz
cd mongo-1.6.10
/app/local/php/bin/phpize
./configure --with-php-config=/app/local/php/bin/php-config
make && make install

#redis
cd /app/local
tar zxvf redis-2.2.7.tgz
cd redis-2.2.7
/app/local/php/bin/phpize
./configure --with-php-config=/app/local/php/bin/php-config
make && make install

#php.ini
vi /app/local/php/etc/php.ini  

[memcached]  
extension=memcached.so
[mongodb]  
extension=mongo.so 
[redis]  
extension=redis.so 

#重启生效
service php-fpm restart
php -i | grep php.ini
php -m

```

## 自动化部署

>服务器的上传目录可以自定义，安装目录默认统一修改为/app/{local,data}，执行脚本为web.sh

``` bash
file://E:\QQDownload\LTMP     (2 folders, 5 files, 27.66 MB, 30.76 MB in total.)
│  httpd-2.2.29.tar.gz     7.19 MB
│  pcre-8.37.tar.gz     1.95 MB
│  php-5.5.27.tar.gz     16.95 MB
│  tengine-2.1.0.tar.gz     1.58 MB
│  web.sh     4.10 KB
├─init     (1 folders, 12 files, 91.42 KB, 92.23 KB in total.)
│  │  allow.conf     35 bytes
│  │  bashrc     2.99 KB
│  │  deny.conf     35 bytes
│  │  limits.conf     1.86 KB
│  │  my.cnf     1.99 KB
│  │  mysqld     8.39 KB
│  │  nginx     2.22 KB
│  │  nginx.conf     1.34 KB
│  │  php-fpm     2.30 KB
│  │  php-fpm.conf     416 bytes
│  │  php.ini     67.83 KB
│  │  sysctl.conf     2.03 KB
│  └─vhosts     (0 folders, 1 files, 826 bytes, 826 bytes in total.)
│          localhost.conf     826 bytes
└─src     (0 folders, 6 files, 3.01 MB, 3.01 MB in total.)
        libmcrypt-2.5.8.tar.gz     1.27 MB
        mcrypt-2.6.8.tar.gz     460.85 KB
        memcache-3.0.8.tgz     68.87 KB
        mhash-0.9.9.9.tar.gz     909.61 KB
        mongo-1.6.10.tgz     204.19 KB
        redis-2.2.7.tgz     131.19 KB


#web.sh

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
sed 's/MAILTO=root/MAILTO=""/g' /etc/crontab
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
#安装Tengine
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



```











