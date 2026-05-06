# power-httptrace 部署说明

环境： 4.19.90-24.4.v2101.ky10.x86_64

------

## 一、安装

```shell
rpm -ivh power-httptrace-1.0.0-1.ky10.x86_64.rpm

# 目录构成
/app/log/power-httptrace   # 日志目录
/app/soft/power-httptrace  # 安装目录
/app/soft/power-httptrace/bin
/app/soft/power-httptrace/bin/httptrace # 执行文件
/etc/logrotate.d/power-httptrace # 日志轮转
/etc/sysconfig/power-httptrace # 配置参数
/usr/lib/systemd/system/power-httptrace.service # 启动文件
```



## 二、配置

### 2.1 获取国密 key 和 iv 进行redis密码加密

```shell
/app/soft/power-httptrace/bin/httptrace --help
power-httptrace 工具使用说明
=====================================
固定 SM4 密钥 (key): 4gppTsa7bJUKc76t
固定 SM4 偏移量 (iv): T465lnDSeDSfXe6a
=====================================
其他命令行参数:
......

# 或者直接使用工具进行加密
/app/soft/power-httptrace/bin/httptrace -sm4encryptStr "Powersi@redis202312"
加密结果： 9/L16DcUm3zIJgui54F/hayuh/bsXcdLdv3De12EkH4=

```

### 2.2 配置说明

```shell
cat /etc/sysconfig/power-httptrace
HTTPTRACE_ARGS="-print-summary=false \
-print-http=false -debug-kernel=true  -log-interval 10s  \
-workers 2  -redis-db 6   -redis-addr core.redis.powerredis.core.powercloud.com:16379   -redis-password 9/L16DcUm3zIJgui54F/hayuh/bsXcdLdv3De12EkH4="

-print-summary 是否打印调用摘要日志
-print-http 是否打印明细日志到控制台
-debug-kernel 内核调试信息，
-log-interval 日志打印间隔
-workers 工作线程数 2

改动点：
-redis-db 库
-redis-addr  redisAddr:port
-redis-password redis国密加密后的密码


```



## 三、启动

```shell
# 启动
systemctl start power-httptrace

# 停止
systemctl stop  power-httptrace
 
# 状态查看
systemctl status  power-httptrace

# 日志查看
tail -400f /app/log/power-httptrace/console.log
```





