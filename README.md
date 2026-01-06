# XG_SQL

> 公众号 : XG小刚
>
> 项目地址：https://github.com/xiaogang000/XG_SQL

SQL注入辅助判断工具，基于xiasql二开，原版链接：https://github.com/smxiazi/xia_sql

```
本工具仅用于授权测试，请勿用于非法用途
```

![image-20260102000136204](./img/image-20260102000136204.png)

## 功能

1、优化检测POC：字符型`'''`、`''''`，数字型`/xxgg`、`/1`，order型`/*xxgg*/`、`/*xxgg/`

2、优化json格式检测和中文乱码

3、增加MyBatis检测POC：`#{xxgg}`、`#xxgg}`

4、增加请求速度限制

5、增加noscan_page跳过参数检测

6、增加add_order增加参数检测

![image-20260102000202059](./img/image-20260102000202059.png)

7、增加值为json数据的扫描，支持GET、POST、JSON请求参数内嵌json数据

![image-20260102000245031](./img/image-20260102000245031.png)



保存配置文件`XgSql_config.ini`



## 更新记录

(20260106): XG_SQL V1.5.3

1、更新两个小bug

(20260102): XG_SQL V1.5.2

1、增加值为json数据的扫描，支持GET、POST、JSON请求参数内嵌json数据

2、修复双引号导致请求包格式混乱bug

3、修复若干其他bug